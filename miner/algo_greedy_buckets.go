package miner

import (
	"crypto/ecdsa"
	"errors"
	"math/big"
	"sort"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
)

// / To use it:
// / 1. Copy relevant data from the worker
// / 2. Call buildBlock
// / 2. If new bundles, txs arrive, call buildBlock again
// / This struct lifecycle is tied to 1 block-building task
type greedyBucketsBuilder struct {
	inputEnvironment *environment
	chainData        chainData
	builderKey       *ecdsa.PrivateKey
	interrupt        *atomic.Int32
	gasUsedMap       map[*txWithMinerFee]uint64
	algoConf         algorithmConfig
}

func newGreedyBucketsBuilder(
	chain *core.BlockChain, chainConfig *params.ChainConfig, algoConf *algorithmConfig,
	blacklist map[common.Address]struct{}, env *environment, key *ecdsa.PrivateKey, interrupt *atomic.Int32,
) *greedyBucketsBuilder {
	if algoConf == nil {
		algoConf = &algorithmConfig{
			EnforceProfit:          true,
			ProfitThresholdPercent: defaultProfitThresholdPercent,
		}
	}
	return &greedyBucketsBuilder{
		inputEnvironment: env,
		chainData:        chainData{chainConfig: chainConfig, chain: chain, blacklist: blacklist},
		builderKey:       key,
		interrupt:        interrupt,
		gasUsedMap:       make(map[*txWithMinerFee]uint64),
		algoConf:         *algoConf,
	}
}

// CutoffPriceFromOrder returns the cutoff price for a given order based on the cutoff percent.
// For example, if the cutoff percent is 90, the cutoff price will be 90% of the order price, rounded down to the nearest integer.
func CutoffPriceFromOrder(order *txWithMinerFee, cutoffPercent int) *big.Int {
	return common.PercentOf(order.Price(), cutoffPercent)
}

// IsOrderInPriceRange returns true if the order price is greater than or equal to the minPrice.
func IsOrderInPriceRange(order *txWithMinerFee, minPrice *big.Int) bool {
	return order.Price().Cmp(minPrice) >= 0
}

func (b *greedyBucketsBuilder) commit(envDiff *environmentDiff,
	transactions []*txWithMinerFee,
	orders *transactionsByPriceAndNonce,
	gasUsedMap map[*txWithMinerFee]uint64, retryMap map[*txWithMinerFee]int, retryLimit int,
) ([]types.SimulatedBundle, []types.UsedSBundle) {
	var (
		algoConf = b.algoConf

		usedBundles  []types.SimulatedBundle
		usedSbundles []types.UsedSBundle

		CheckRetryOrderAndReinsert = func(
			order *txWithMinerFee, orders *transactionsByPriceAndNonce,
			retryMap map[*txWithMinerFee]int, retryLimit int,
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
				orders.Push(order)
			}

			return isRetryable
		}
	)

	for _, order := range transactions {
		if tx := order.Tx(); tx != nil {
			receipt, skip, err := envDiff.commitTx(tx.Resolve().Tx, b.chainData)
			if err != nil {
				log.Trace("could not apply tx", "hash", tx.Resolve().Tx.Hash(), "err", err)

				// attempt to retry transaction commit up to retryLimit
				// the gas used is set for the order to re-calculate profit of the transaction for subsequent retries
				if receipt != nil {
					// if the receipt is nil we don't attempt to retry the transaction - this is to mitigate abuse since
					// without a receipt the default profit calculation for a transaction uses the gas limit which
					// can cause the transaction to always be first in any profit-sorted transaction list
					gasUsedMap[order] = receipt.GasUsed
					CheckRetryOrderAndReinsert(order, orders, retryMap, retryLimit)
				}
				continue
			}

			if skip == shiftTx {
				orders.ShiftAndPushByAccountForTx(tx)
			}

			effGapPrice, err := tx.Resolve().Tx.EffectiveGasTip(envDiff.baseEnvironment.header.BaseFee)
			if err == nil {
				log.Trace("Included tx", "EGP", effGapPrice.String(), "gasUsed", receipt.GasUsed)
			}
		} else if bundle := order.Bundle(); bundle != nil {
			err := envDiff.commitBundle(bundle, b.chainData, b.interrupt, algoConf)
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
				continue
			}

			log.Trace("Included bundle", "bundleEGP", bundle.MevGasPrice.String(),
				"gasUsed", bundle.TotalGasUsed, "ethToCoinbase", ethIntToFloat(bundle.TotalEth))
			usedBundles = append(usedBundles, *bundle)
		} else if sbundle := order.SBundle(); sbundle != nil {
			usedEntry := types.UsedSBundle{
				Bundle: sbundle.Bundle,
			}
			err := envDiff.commitSBundle(sbundle, b.chainData, b.interrupt, b.builderKey, algoConf)
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
					if ok := CheckRetryOrderAndReinsert(order, orders, retryMap, retryLimit); !ok {
						usedEntry.Success = false
						usedSbundles = append(usedSbundles, usedEntry)
					}
				}
				continue
			}

			log.Trace("Included sbundle", "bundleEGP", sbundle.MevGasPrice.String(), "ethToCoinbase", ethIntToFloat(sbundle.Profit))
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

func (b *greedyBucketsBuilder) mergeOrdersIntoEnvDiff(
	envDiff *environmentDiff, orders *transactionsByPriceAndNonce) ([]types.SimulatedBundle, []types.UsedSBundle,
) {
	if orders.Peek() == nil {
		return nil, nil
	}

	const retryLimit = 1

	var (
		baseFee            = envDiff.baseEnvironment.header.BaseFee
		retryMap           = make(map[*txWithMinerFee]int)
		usedBundles        []types.SimulatedBundle
		usedSbundles       []types.UsedSBundle
		transactions       []*txWithMinerFee
		priceCutoffPercent = b.algoConf.PriceCutoffPercent

		SortInPlaceByProfit = func(baseFee *big.Int, transactions []*txWithMinerFee, gasUsedMap map[*txWithMinerFee]uint64) {
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
				bundles, sbundles := b.commit(envDiff, transactions, orders, b.gasUsedMap, retryMap, retryLimit)
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
				bundles, sbundles := b.commit(envDiff, transactions, orders, b.gasUsedMap, retryMap, retryLimit)
				usedBundles = append(usedBundles, bundles...)
				usedSbundles = append(usedSbundles, sbundles...)
				transactions = nil
			}
			minPrice = CutoffPriceFromOrder(order, priceCutoffPercent)
		}
	}

	return usedBundles, usedSbundles
}

func (b *greedyBucketsBuilder) buildBlock(simBundles []types.SimulatedBundle, simSBundles []*types.SimSBundle, transactions map[common.Address][]*txpool.LazyTransaction) (*environment, []types.SimulatedBundle, []types.UsedSBundle) {
	orders := newTransactionsByPriceAndNonce(b.inputEnvironment.signer, transactions, simBundles, simSBundles, b.inputEnvironment.header.BaseFee)
	envDiff := newEnvironmentDiff(b.inputEnvironment.copy())
	usedBundles, usedSbundles := b.mergeOrdersIntoEnvDiff(envDiff, orders)
	envDiff.applyToBaseEnv()
	return envDiff.baseEnvironment, usedBundles, usedSbundles
}
