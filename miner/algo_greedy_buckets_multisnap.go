package miner

import (
	"crypto/ecdsa"
	"errors"
	"sort"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// / To use it:
// / 1. Copy relevant data from the worker
// / 2. Call buildBlock
// / 2. If new bundles, txs arrive, call buildBlock again
// / This struct lifecycle is tied to 1 block-building task
type greedyBucketsMultiSnapBuilder struct {
	inputEnvironment *environment
	chainData        chainData
	builderKey       *ecdsa.PrivateKey
	interrupt        *atomic.Int32
	gasUsedMap       map[*txWithMinerFee]uint64
	algoConf         algorithmConfig
}

func newGreedyBucketsMultiSnapBuilder(
	chain *core.BlockChain, chainConfig *params.ChainConfig, algoConf *algorithmConfig,
	blacklist map[common.Address]struct{}, env *environment, key *ecdsa.PrivateKey, interrupt *atomic.Int32,
) *greedyBucketsMultiSnapBuilder {
	if algoConf == nil {
		panic("algoConf cannot be nil")
	}

	return &greedyBucketsMultiSnapBuilder{
		inputEnvironment: env,
		chainData:        chainData{chainConfig: chainConfig, chain: chain, blacklist: blacklist},
		builderKey:       key,
		interrupt:        interrupt,
		gasUsedMap:       make(map[*txWithMinerFee]uint64),
		algoConf:         *algoConf,
	}
}

func (b *greedyBucketsMultiSnapBuilder) commit(changes *envChanges,
	transactions []*txWithMinerFee,
	orders *transactionsByPriceAndNonce,
	gasUsedMap map[*txWithMinerFee]uint64, retryMap map[*txWithMinerFee]int, retryLimit int,
) ([]types.SimulatedBundle, []types.UsedSBundle) {
	var (
		algoConf = b.algoConf

		usedBundles  []types.SimulatedBundle
		usedSbundles []types.UsedSBundle
	)

	for _, order := range transactions {
		if err := changes.env.state.NewMultiTxSnapshot(); err != nil {
			log.Error("Failed to create new multi-tx snapshot", "err", err)
			return usedBundles, usedSbundles
		}

		orderFailed := false

		if lazyTx := order.Tx(); lazyTx != nil {
			tx := lazyTx.Resolve()
			if tx == nil {
				log.Trace("Ignoring evicted transaction", "hash", lazyTx.Hash)
				orders.Pop()
				continue
			}
			receipt, skip, err := changes.commitTx(tx, b.chainData)
			orderFailed = err != nil
			if err != nil {
				log.Trace("could not apply tx", "hash", tx.Hash(), "err", err)

				// attempt to retry transaction commit up to retryLimit
				// the gas used is set for the order to re-calculate profit of the transaction for subsequent retries
				if receipt != nil {
					// if the receipt is nil we don't attempt to retry the transaction - this is to mitigate abuse since
					// without a receipt the default profit calculation for a transaction uses the gas limit which
					// can cause the transaction to always be first in any profit-sorted transaction list
					gasUsedMap[order] = receipt.GasUsed
					CheckRetryOrderAndReinsert(order, orders, retryMap, retryLimit)
				}
			} else {
				if skip == shiftTx {
					orders.ShiftAndPushByAccountForTx(tx)
				}
				// we don't check for error here because if EGP returns error, it would have been caught and returned by commitTx
				effGapPrice, _ := tx.EffectiveGasTip(changes.env.header.BaseFee)
				log.Trace("Included tx", "EGP", effGapPrice.String(), "gasUsed", receipt.GasUsed)
			}
		} else if bundle := order.Bundle(); bundle != nil {
			err := changes.commitBundle(bundle, b.chainData, algoConf)
			orderFailed = err != nil
			if err != nil {
				log.Trace("Could not apply bundle", "bundle", bundle.OriginalBundle.Hash, "err", err)

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
			} else {
				log.Trace("Included bundle", "bundleEGP", bundle.MevGasPrice.String(),
					"gasUsed", bundle.TotalGasUsed, "ethToCoinbase", ethIntToFloat(bundle.EthSentToCoinbase))
				usedBundles = append(usedBundles, *bundle)
			}
		} else if sbundle := order.SBundle(); sbundle != nil {
			err := changes.CommitSBundle(sbundle, b.chainData, b.builderKey, algoConf)
			orderFailed = err != nil
			usedEntry := types.UsedSBundle{
				Bundle:  sbundle.Bundle,
				Success: err == nil,
			}

			isValidOrNotRetried := true
			if err != nil {
				log.Trace("Could not apply sbundle", "bundle", sbundle.Bundle.Hash(), "err", err)

				var e *lowProfitError
				if errors.As(err, &e) {
					if e.ActualEffectiveGasPrice != nil {
						order.SetPrice(e.ActualEffectiveGasPrice)
					}

					if e.ActualProfit != nil {
						order.SetProfit(e.ActualProfit)
					}

					// if the sbundle was not included due to low profit, we can retry the bundle
					if ok := CheckRetryOrderAndReinsert(order, orders, retryMap, retryLimit); ok {
						isValidOrNotRetried = false
					}
				}
			} else {
				log.Trace("Included sbundle", "bundleEGP", sbundle.MevGasPrice.String(), "ethToCoinbase", ethIntToFloat(sbundle.Profit))
			}

			if isValidOrNotRetried {
				usedSbundles = append(usedSbundles, usedEntry)
			}
		} else {
			// note: this should never happen because we should not be inserting invalid transaction types into
			// the orders heap
			panic("unsupported order type found")
		}

		if orderFailed {
			if err := changes.env.state.MultiTxSnapshotRevert(); err != nil {
				log.Error("Failed to revert snapshot", "err", err)
				return usedBundles, usedSbundles
			}
		} else {
			if err := changes.env.state.MultiTxSnapshotCommit(); err != nil {
				log.Error("Failed to commit snapshot", "err", err)
				return usedBundles, usedSbundles
			}
		}
	}
	return usedBundles, usedSbundles
}

func (b *greedyBucketsMultiSnapBuilder) mergeOrdersAndApplyToEnv(
	orders *transactionsByPriceAndNonce,
) (*environment, []types.SimulatedBundle, []types.UsedSBundle) {
	if orders.Peek() == nil {
		return b.inputEnvironment, nil, nil
	}

	changes, err := newEnvChanges(b.inputEnvironment)
	if err != nil {
		log.Error("Failed to create new environment changes", "err", err)
		return b.inputEnvironment, nil, nil
	}

	const retryLimit = 1

	var (
		baseFee            = uint256.MustFromBig(changes.env.header.BaseFee)
		retryMap           = make(map[*txWithMinerFee]int)
		usedBundles        []types.SimulatedBundle
		usedSbundles       []types.UsedSBundle
		transactions       []*txWithMinerFee
		priceCutoffPercent = b.algoConf.PriceCutoffPercent

		SortInPlaceByProfit = func(baseFee *uint256.Int, transactions []*txWithMinerFee, gasUsedMap map[*txWithMinerFee]uint64) {
			sort.SliceStable(transactions, func(i, j int) bool {
				return transactions[i].Profit(baseFee, gasUsedMap[transactions[i]]).Cmp(transactions[j].Profit(baseFee, gasUsedMap[transactions[j]])) > 0
			})
		}
	)

	minPrice := CutoffPriceFromOrder(orders.Peek(), priceCutoffPercent)
	for {
		order := orders.Peek()
		if order == nil {
			if len(transactions) != 0 {
				SortInPlaceByProfit(baseFee, transactions, b.gasUsedMap)
				bundles, sbundles := b.commit(changes, transactions, orders, b.gasUsedMap, retryMap, retryLimit)
				usedBundles = append(usedBundles, bundles...)
				usedSbundles = append(usedSbundles, sbundles...)
				transactions = nil
				// re-run since committing transactions may have pushed higher nonce transactions, or previously
				// failed transactions back into orders heap
				continue
			}
			break
		}

		if ok := IsOrderInPriceRange(order, minPrice); ok {
			orders.Pop()
			transactions = append(transactions, order)
		} else {
			if len(transactions) != 0 {
				SortInPlaceByProfit(baseFee, transactions, b.gasUsedMap)
				bundles, sbundles := b.commit(changes, transactions, orders, b.gasUsedMap, retryMap, retryLimit)
				usedBundles = append(usedBundles, bundles...)
				usedSbundles = append(usedSbundles, sbundles...)
				transactions = nil
			}
			minPrice = CutoffPriceFromOrder(order, priceCutoffPercent)
		}
	}

	if err := changes.apply(); err != nil {
		log.Error("Failed to apply changes", "err", err)
		return b.inputEnvironment, nil, nil
	}

	return changes.env, usedBundles, usedSbundles
}

func (b *greedyBucketsMultiSnapBuilder) buildBlock(simBundles []types.SimulatedBundle, simSBundles []*types.SimSBundle, transactions map[common.Address][]*txpool.LazyTransaction) (*environment, []types.SimulatedBundle, []types.UsedSBundle) {
	orders := newTransactionsByPriceAndNonce(b.inputEnvironment.signer, transactions, simBundles, simSBundles, b.inputEnvironment.header.BaseFee)
	return b.mergeOrdersAndApplyToEnv(orders)
}
