package miner

import (
	"container/heap"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"math/big"
)

// / To use it:
// / 1. Copy relevant data from the worker
// / 2. Call buildBlock
// / 2. If new bundles, txs arrive, call buildBlock again
// / This struct lifecycle is tied to 1 block-building task
type greedyProfitBuilder struct {
	inputEnvironment *environment
	chainData        chainData
	builderKey       *ecdsa.PrivateKey
	interrupt        *int32
	gasUsedMap       map[*types.TxWithMinerFee]uint64
	algoConf         algorithmConfig
}

func newGreedyProfitBuilder(
	chain *core.BlockChain, chainConfig *params.ChainConfig, algoConf *algorithmConfig,
	blacklist map[common.Address]struct{}, env *environment, key *ecdsa.PrivateKey, interrupt *int32,
) (*greedyProfitBuilder, error) {
	if algoConf == nil {
		return nil, fmt.Errorf("error initializing greedy profit builder - algorithm configuration not specified")
	}
	return &greedyProfitBuilder{
		inputEnvironment: env,
		chainData:        chainData{chainConfig: chainConfig, chain: chain, blacklist: blacklist},
		builderKey:       key,
		interrupt:        interrupt,
		gasUsedMap:       make(map[*types.TxWithMinerFee]uint64),
		algoConf:         *algoConf,
	}, nil
}

func (b *greedyProfitBuilder) mergeOrdersIntoEnvDiff(
	envDiff *environmentDiff, orders *txsByProfitAndTime) ([]types.SimulatedBundle, []types.UsedSBundle,
) {
	if orders.Peek() == nil {
		return nil, nil
	}

	const retryLimit = 1

	var (
		usedBundles  []types.SimulatedBundle
		usedSbundles []types.UsedSBundle
		retryMap     = make(map[*types.TxWithMinerFee]int)

		CheckRetryOrderAndReinsert = func(
			order *types.TxWithMinerFee, orders *txsByProfitAndTime,
			retryMap map[*types.TxWithMinerFee]int, retryLimit int,
		) bool {
			var isRetryable bool = false
			if retryCount, exists := retryMap[order]; exists {
				if retryCount != retryLimit {
					isRetryable = true
					retryMap[order] = retryCount + 1
				}
			} else {
				retryMap[order] = 0
				isRetryable = true
			}

			if isRetryable {
				heap.Push(orders, order)
			}

			return isRetryable
		}
	)

	for {
		order := orders.Peek()
		if order == nil {
			break
		}

		if tx := order.Tx(); tx != nil {
			receipt, skip, err := envDiff.commitTx(tx, b.chainData)
			switch skip {
			case shiftTx:
				orders.Shift()
			case popTx:
				heap.Pop(orders)
			}

			if err != nil {
				log.Trace("could not apply tx", "hash", tx.Hash(), "err", err)

				// attempt to retry transaction commit up to retryLimit
				// the gas used is set for the order to re-calculate profit of the transaction for subsequent retries
				if receipt != nil {
					// if the receipt is nil we don't attempt to retry the transaction - this is to mitigate abuse since
					// without a receipt the default profit calculation for a transaction uses the gas limit which
					// can cause the transaction to always be first in any profit-sorted transaction list
					b.gasUsedMap[order] = receipt.GasUsed
					CheckRetryOrderAndReinsert(order, orders, retryMap, retryLimit)
				}
				continue
			}
		} else if bundle := order.Bundle(); bundle != nil {
			err := envDiff.commitBundle(bundle, b.chainData, b.interrupt, b.algoConf)
			heap.Pop(orders)
			if err != nil {
				log.Trace("failed to commit bundle",
					"size", len(bundle.OriginalBundle.Txs), "err", err)
				var e *lowProfitError
				if errors.As(err, &e) {
					if e.ActualEffectiveGasPrice != nil {
						order.SetPrice(e.ActualEffectiveGasPrice)
					}

					if e.ActualProfit != nil {
						order.SetProfit(e.ActualProfit)
					}
					// if the bundle was not included due to low profit, we can retry the bundle
					CheckRetryOrderAndReinsert(order, orders, retryMap, retryLimit)
				}
				continue
			}

			usedBundles = append(usedBundles, *bundle)
		} else if sbundle := order.SBundle(); sbundle != nil {
			usedEntry := types.UsedSBundle{
				Bundle: sbundle.Bundle,
			}
			err := envDiff.commitSBundle(sbundle, b.chainData, b.interrupt, b.builderKey, b.algoConf)
			heap.Pop(orders)
			if err != nil {
				log.Trace("Could not apply sbundle",
					"bundle", sbundle.Bundle.Hash(), "size", len(sbundle.Bundle.Body), "err", err)

				var e *lowProfitError
				if errors.As(err, &e) {
					if e.ActualEffectiveGasPrice != nil {
						order.SetPrice(e.ActualEffectiveGasPrice)
					}

					if e.ActualProfit != nil {
						order.SetProfit(e.ActualProfit)
					}

					// if the sbundle was not included due to low profit, we can retry the bundle
					if ok := CheckRetryOrderAndReinsert(order, orders, retryMap, retryLimit); !ok {
						usedEntry.Success = false
						usedSbundles = append(usedSbundles, usedEntry)
					}
				} else {
					usedEntry.Success = false
					usedSbundles = append(usedSbundles, usedEntry)
				}
				continue
			}

			usedEntry.Success = true
			usedSbundles = append(usedSbundles, usedEntry)
		} else {
			// note: this should never happen because we should not be inserting invalid transaction types into
			// the orders heap
			panic("unsupported order type found")
		}
	}
	return usedBundles, usedSbundles
}

func (b *greedyProfitBuilder) buildBlock(simBundles []types.SimulatedBundle, simSBundles []*types.SimSBundle, transactions map[common.Address]types.Transactions) (*environment, []types.SimulatedBundle, []types.UsedSBundle) {
	orders := newTransactionsByProfitAndNonce(b.inputEnvironment.signer, transactions, simBundles, simSBundles, b.inputEnvironment.header.BaseFee)
	envDiff := newEnvironmentDiff(b.inputEnvironment.copy())
	usedBundles, usedSbundles := b.mergeOrdersIntoEnvDiff(envDiff, orders)
	envDiff.applyToBaseEnv()
	return envDiff.baseEnvironment, usedBundles, usedSbundles
}

func newTransactionsByProfitAndNonce(
	signer types.Signer, txs map[common.Address]types.Transactions,
	bundles []types.SimulatedBundle, sbundles []*types.SimSBundle, baseFee *big.Int) *txsByProfitAndTime {
	// Initialize a profit and received time based heap with the head transactions
	heads := make([]*types.TxWithMinerFee, 0, len(txs)+len(bundles)+len(sbundles))

	for i := range sbundles {
		wrapped, err := types.NewSBundleWithMinerFee(sbundles[i], baseFee)
		if err != nil {
			continue
		}
		heads = append(heads, wrapped)
	}

	for i := range bundles {
		wrapped, err := types.NewBundleWithMinerFee(&bundles[i], baseFee)
		if err != nil {
			continue
		}
		heads = append(heads, wrapped)
	}

	for from, accTxs := range txs {
		acc, _ := types.Sender(signer, accTxs[0])
		wrapped, err := types.NewTxWithMinerFee(accTxs[0], baseFee)
		// Remove transaction if sender doesn't match from, or if wrapping fails.
		if acc != from || err != nil {
			delete(txs, from)
			continue
		}
		heads = append(heads, wrapped)
		txs[from] = accTxs[1:]
	}

	h := txsByProfitAndTime{
		Entries: heads,
		BaseFee: baseFee,
		Txs:     txs,
		Signer:  signer,
	}
	heap.Init(&h)

	return &h
}

// txsByProfitAndTime implements both the sort and the heap interface, making it useful
// for all at once sorting as well as individually adding and removing elements.
type txsByProfitAndTime struct {
	Txs     map[common.Address]types.Transactions // Per account nonce-sorted list of transactions
	Entries []*types.TxWithMinerFee
	BaseFee *big.Int     // Current base fee
	Signer  types.Signer // Signer for the set of transactions
}

func (t *txsByProfitAndTime) Len() int { return len(t.Entries) }

func (t *txsByProfitAndTime) Less(i, j int) bool {
	// If the profits are equal, use the time the transaction was first seen for
	// deterministic sorting
	cmp := t.Entries[i].Profit(t.BaseFee, 0).Cmp(t.Entries[j].Profit(t.BaseFee, 0))
	if cmp == 0 {
		if txI, txJ := t.Entries[i].Tx(), t.Entries[j].Tx(); txI != nil && txJ != nil {
			return txI.Time().Before(txJ.Time())
		} else if bundleI, bundleJ := t.Entries[i].Bundle(), t.Entries[j].Bundle(); bundleI != nil && bundleJ != nil {
			return bundleI.TotalGasUsed <= bundleJ.TotalGasUsed
		} else if t.Entries[i].Bundle() != nil {
			return false
		}

		return true
	}

	return cmp > 0
}
func (t *txsByProfitAndTime) Swap(i, j int) { t.Entries[i], t.Entries[j] = t.Entries[j], t.Entries[i] }

func (t *txsByProfitAndTime) Push(x interface{}) {
	t.Entries = append(t.Entries, x.(*types.TxWithMinerFee))
}

func (t *txsByProfitAndTime) Pop() interface{} {
	old := t.Entries
	n := len(old)
	x := old[n-1]
	old[n-1] = nil
	t.Entries = old[0 : n-1]
	return x
}

func (t *txsByProfitAndTime) Peek() *types.TxWithMinerFee {
	if len(t.Entries) == 0 {
		return nil
	}

	return t.Entries[0]
}

func (t *txsByProfitAndTime) Shift() {
	if tx := t.Entries[0].Tx(); tx != nil {
		acc, _ := types.Sender(t.Signer, tx)
		if txs, ok := t.Txs[acc]; ok && len(txs) > 0 {
			if wrapped, err := types.NewTxWithMinerFee(txs[0], t.BaseFee); err == nil {
				t.Entries[0], t.Txs[acc] = wrapped, txs[1:]
				heap.Fix(t, 0)
				return
			}
		}
	}
	heap.Pop(t)
}
