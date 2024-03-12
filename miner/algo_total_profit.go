package miner

import (
	"container/heap"
	"crypto/ecdsa"
	"errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"math/big"
	"sync"
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
	algoConf         algorithmConfig
}

var heapPool = sync.Pool{
	New: func() interface{} {
		return &txsByProfitAndTime{
			Txs:       make(map[common.Address]types.Transactions, 256),
			Entries:   make([]*types.TxWithMinerFee, 0, 256),
			BaseFee:   new(big.Int),
			Signer:    nil,
			ProfitMap: make(map[common.Hash]big.Int, 256),
		}
	},
}

func newGreedyProfitBuilder(
	chain *core.BlockChain, chainConfig *params.ChainConfig, algoConf *algorithmConfig,
	blacklist map[common.Address]struct{}, env *environment, key *ecdsa.PrivateKey, interrupt *int32,
) *greedyProfitBuilder {
	if algoConf == nil {
		panic("error initializing greedy profit builder - algorithm configuration not specified")
	}

	return &greedyProfitBuilder{
		inputEnvironment: env,
		chainData:        chainData{chainConfig: chainConfig, chain: chain, blacklist: blacklist},
		builderKey:       key,
		interrupt:        interrupt,
		algoConf:         *algoConf,
	}
}

func (b *greedyProfitBuilder) mergeOrdersIntoEnvDiff(
	envDiff *environmentDiff, orders *txsByProfitAndTime) ([]types.SimulatedBundle, []types.UsedSBundle,
) {
	if orders.Peek() == nil {
		return nil, nil
	}

	const retryLimit = 1

	var (
		usedBundles  = make([]types.SimulatedBundle, 0, orders.Len())
		usedSbundles = make([]types.UsedSBundle, 0, orders.Len())
		retryMap     = make(map[*types.TxWithMinerFee]int, orders.Len())

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
					orders.ProfitMap[order.Hash()] = *order.Profit(envDiff.header.BaseFee, receipt.GasUsed)
					CheckRetryOrderAndReinsert(order, orders, retryMap, retryLimit)
				}
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
	orders := heapPool.Get().(*txsByProfitAndTime)
	for k := range orders.Txs {
		delete(orders.Txs, k)
	}
	orders.Entries = orders.Entries[:0]
	orders.BaseFee = b.inputEnvironment.header.BaseFee
	orders.Signer = b.inputEnvironment.signer
	for k := range orders.ProfitMap {
		delete(orders.ProfitMap, k)
	}
	defer heapPool.Put(orders)

	newTransactionsByProfitAndNonce(orders, b.inputEnvironment.signer, transactions, simBundles, simSBundles, b.inputEnvironment.header.BaseFee)

	const retryLimit = 1

	var (
		usedBundles  []types.SimulatedBundle
		usedSbundles []types.UsedSBundle
		retryMap     = make(map[*types.TxWithMinerFee]int, orders.Len())

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

	changes, err := newEnvChanges(b.inputEnvironment)
	if err != nil {
		log.Error("Failed to create new environment changes", "err", err)
		return b.inputEnvironment, nil, nil
	}

	for {
		order := orders.Peek()
		if order == nil {
			break
		}

		orderFailed := false
		if err := changes.env.state.NewMultiTxSnapshot(); err != nil {
			log.Error("Failed to create snapshot", "err", err)
			return b.inputEnvironment, usedBundles, usedSbundles
		}

		if tx := order.Tx(); tx != nil {
			receipt, skip, err := changes.commitTx(tx, b.chainData)
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
					orders.ProfitMap[order.Hash()] = *order.Profit(changes.env.header.BaseFee, receipt.GasUsed)
					CheckRetryOrderAndReinsert(order, orders, retryMap, retryLimit)
				}
			}
		} else if bundle := order.Bundle(); bundle != nil {
			err := changes.commitBundle(bundle, b.chainData, b.algoConf)
			heap.Pop(orders)
			orderFailed = err != nil

			if err == nil {
				usedBundles = append(usedBundles, *bundle)
			}
		} else if sbundle := order.SBundle(); sbundle != nil {
			err := changes.CommitSBundle(sbundle, b.chainData, b.builderKey, b.algoConf)
			heap.Pop(orders)
			orderFailed = err != nil
			usedEntry := types.UsedSBundle{
				Bundle:  sbundle.Bundle,
				Success: !orderFailed,
			}

			usedSbundles = append(usedSbundles, usedEntry)
		} else {
			// note: this should never happen because we should not be inserting invalid transaction types into
			// the orders heap
			panic("unsupported order type found")
		}

		if orderFailed {
			if err := changes.env.state.MultiTxSnapshotRevert(); err != nil {
				log.Error("Failed to revert snapshot", "err", err)
				return b.inputEnvironment, usedBundles, usedSbundles
			}
		} else {
			if err := changes.env.state.MultiTxSnapshotCommit(); err != nil {
				log.Error("Failed to commit snapshot", "err", err)
				return b.inputEnvironment, usedBundles, usedSbundles
			}
		}
	}

	if err := changes.apply(); err != nil {
		log.Error("Failed to apply changes", "err", err)
		return b.inputEnvironment, usedBundles, usedSbundles
	}

	return changes.env, usedBundles, usedSbundles
}

func newTransactionsByProfitAndNonce(
	t *txsByProfitAndTime, signer types.Signer, txs map[common.Address]types.Transactions,
	bundles []types.SimulatedBundle, sbundles []*types.SimSBundle, baseFee *big.Int) {
	// Initialize a profit and received time based heap with the head transactions
	heads := t.Entries
	profits := t.ProfitMap
	//heads := make([]*types.TxWithMinerFee, 0, len(txs)+len(bundles)+len(sbundles))
	//profits := make(map[common.Hash]big.Int, len(txs)+len(bundles)+len(sbundles))

	for i := range sbundles {
		wrapped, err := types.NewSBundleWithMinerFee(sbundles[i], baseFee)
		if err != nil {
			continue
		}
		profits[sbundles[i].Bundle.Hash()] = *sbundles[i].Profit
		heads = append(heads, wrapped)
	}

	for i := range bundles {
		wrapped, err := types.NewBundleWithMinerFee(&bundles[i], baseFee)
		if err != nil {
			continue
		}
		profits[bundles[i].OriginalBundle.Hash] = *bundles[i].EthSentToCoinbase
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
		profits[accTxs[0].Hash()] = *wrapped.Profit(baseFee, 0)
		heads = append(heads, wrapped)
		txs[from] = accTxs[1:]
	}

	t.Entries = heads
	t.ProfitMap = profits
	heap.Init(t)
}

// txsByProfitAndTime implements both the sort and the heap interface, making it useful
// for all at once sorting as well as individually adding and removing elements.
type txsByProfitAndTime struct {
	Txs       map[common.Address]types.Transactions // Per account nonce-sorted list of transactions
	Entries   []*types.TxWithMinerFee
	BaseFee   *big.Int     // Current base fee
	Signer    types.Signer // Signer for the set of transactions
	ProfitMap map[common.Hash]big.Int
}

func (t *txsByProfitAndTime) Len() int { return len(t.Entries) }

func (t *txsByProfitAndTime) Less(i, j int) bool {
	// If the profits are equal, use the time the transaction was first seen for
	// deterministic sorting
	var (
		iOrder, jOrder   = t.Entries[i], t.Entries[j]
		iProfit, jProfit = t.ProfitMap[iOrder.Hash()], t.ProfitMap[jOrder.Hash()]
		cmp              = (&iProfit).Cmp(&jProfit)
	)

	if cmp == 0 {
		var (
			iTx, iBundle, iSBundle = iOrder.Tx(), iOrder.Bundle(), iOrder.SBundle()
			jTx, jBundle, jSBundle = jOrder.Tx(), jOrder.Bundle(), jOrder.SBundle()
		)
		if iTx != nil {
			if jTx != nil {
				return iTx.Time().Before(jTx.Time())
			}
			return false
		}

		if iBundle != nil {
			if jBundle != nil {
				return iBundle.TotalGasUsed <= jBundle.TotalGasUsed
			}

			if jSBundle != nil {
				return iBundle.MevGasPrice.Cmp(jSBundle.MevGasPrice) <= 0
			}

			return true
		}

		if iSBundle != nil {
			if jSBundle != nil {
				return iSBundle.MevGasPrice.Cmp(jSBundle.MevGasPrice) <= 0
			}

			if jBundle != nil {
				return iSBundle.MevGasPrice.Cmp(jBundle.MevGasPrice) <= 0
			}

			return true
		}

		return false
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
