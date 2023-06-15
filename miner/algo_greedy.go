package miner

import (
	"crypto/ecdsa"
	"math/big"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
)

// / To use it:
// / 1. Copy relevant data from the worker
// / 2. Call buildBlock
// / 2. If new bundles, txs arrive, call buildBlock again
// / This struct lifecycle is tied to 1 block-building task
type greedyBuilder struct {
	inputEnvironment *environment
	chainData        chainData
	builderKey       *ecdsa.PrivateKey
	interrupt        *int32
	algoType         AlgoType
}

func newGreedyBuilder(
	chain *core.BlockChain, chainConfig *params.ChainConfig,
	blacklist map[common.Address]struct{}, env *environment, key *ecdsa.PrivateKey, interrupt *int32, algo AlgoType,
) *greedyBuilder {
	return &greedyBuilder{
		inputEnvironment: env,
		chainData:        chainData{chainConfig, chain, blacklist},
		builderKey:       key,
		interrupt:        interrupt,
		algoType:         algo,
	}
}

func (b *greedyBuilder) commit(
	envDiff *environmentDiff, transactions []*types.TxWithMinerFee, orders *types.TransactionsByPriceAndNonce,
) ([]types.SimulatedBundle, []types.UsedSBundle) {
	var (
		usedBundles  []types.SimulatedBundle
		usedSbundles []types.UsedSBundle
	)

	for _, order := range transactions {
		if tx := order.Tx(); tx != nil {
			receipt, skip, err := envDiff.commitTx(tx, b.chainData)
			if skip == shiftTx {
				orders.ShiftAndPushByAccountForTx(tx)
			}

			if err != nil {
				log.Trace("could not apply tx", "hash", tx.Hash(), "err", err)
				// TODO: handle retry
				continue
			}

			effGapPrice, err := tx.EffectiveGasTip(envDiff.baseEnvironment.header.BaseFee)
			if err == nil {
				log.Trace("Included tx", "EGP", effGapPrice.String(), "gasUsed", receipt.GasUsed)
			}
		} else if bundle := order.Bundle(); bundle != nil {
			err := envDiff.commitBundle(bundle, b.chainData, b.interrupt, true)
			if err != nil {
				log.Trace("Could not apply bundle", "bundle", bundle.OriginalBundle.Hash, "err", err)
				// TODO: handle retry
				continue
			}

			log.Trace("Included bundle", "bundleEGP", bundle.MevGasPrice.String(),
				"gasUsed", bundle.TotalGasUsed, "ethToCoinbase", ethIntToFloat(bundle.TotalEth))
			usedBundles = append(usedBundles, *bundle)
		} else if sbundle := order.SBundle(); sbundle != nil {
			usedEntry := types.UsedSBundle{
				Bundle: sbundle.Bundle,
			}
			err := envDiff.commitSBundle(sbundle, b.chainData, b.interrupt, b.builderKey, true)
			if err != nil {
				log.Trace("Could not apply sbundle", "bundle", sbundle.Bundle.Hash(), "err", err)
				// TODO: handle retry
				usedEntry.Success = false
				usedSbundles = append(usedSbundles, usedEntry)
				continue
			}

			log.Trace("Included sbundle", "bundleEGP", sbundle.MevGasPrice.String(), "ethToCoinbase", ethIntToFloat(sbundle.Profit))
			usedEntry.Success = true
			usedSbundles = append(usedSbundles, usedEntry)
		}
	}
	return usedBundles, usedSbundles
}

func (b *greedyBuilder) mergeGreedyBuckets(
	envDiff *environmentDiff, orders *types.TransactionsByPriceAndNonce) (
	[]types.SimulatedBundle, []types.UsedSBundle,
) {
	if orders.Peek() == nil {
		return nil, nil
	}

	var (
		usedBundles       []types.SimulatedBundle
		usedSbundles      []types.UsedSBundle
		transactionBucket []*types.TxWithMinerFee
		percent           = big.NewFloat(0.9)

		InitializeBucket = func(order *types.TxWithMinerFee) [1]*big.Int {
			floorPrice := new(big.Float).Mul(new(big.Float).SetInt(order.Price()), percent)
			round, _ := floorPrice.Int64()
			return [1]*big.Int{big.NewInt(round)}
		}

		IsOrderInPriceRange = func(order *types.TxWithMinerFee, minPrice *big.Int) bool {
			return order.Price().Cmp(minPrice) > -1
		}

		SortByProfit = func(transactions []*types.TxWithMinerFee) {
			sort.SliceStable(transactions, func(i, j int) bool {
				var (
					iProfit = transactions[i].Profit()
					jProfit = transactions[j].Profit()
				)

				return iProfit.Cmp(jProfit) > 0
			})
		}
	)

	bucket := InitializeBucket(orders.Peek())
	for {
		order := orders.Peek()
		if order == nil {
			if len(transactionBucket) != 0 {
				SortByProfit(transactionBucket)
				bundles, sbundles := b.commit(envDiff, transactionBucket, orders)
				usedBundles = append(usedBundles, bundles...)
				usedSbundles = append(usedSbundles, sbundles...)
				transactionBucket = nil
				continue // re-run since committing transactions may have pushed higher nonce transactions back into heap
			}
			// TODO: don't break if there are still retryable transactions
			break
		}

		if ok := IsOrderInPriceRange(order, bucket[0]); ok {
			orders.Pop()
			transactionBucket = append(transactionBucket, order)
		} else {
			if len(transactionBucket) != 0 {
				SortByProfit(transactionBucket)
				bundles, sbundles := b.commit(envDiff, transactionBucket, orders)
				usedBundles = append(usedBundles, bundles...)
				usedSbundles = append(usedSbundles, sbundles...)
				transactionBucket = nil
			}
			bucket = InitializeBucket(order)
		}
	}

	return usedBundles, usedSbundles
}

func (b *greedyBuilder) mergeGreedy(envDiff *environmentDiff, orders *types.TransactionsByPriceAndNonce) ([]types.SimulatedBundle, []types.UsedSBundle) {
	var (
		usedBundles  []types.SimulatedBundle
		usedSbundles []types.UsedSBundle
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
				orders.Pop()
			}

			if err != nil {
				log.Trace("could not apply tx", "hash", tx.Hash(), "err", err)
				continue
			}
			effGapPrice, err := tx.EffectiveGasTip(envDiff.baseEnvironment.header.BaseFee)
			if err == nil {
				log.Trace("Included tx", "EGP", effGapPrice.String(), "gasUsed", receipt.GasUsed)
			}
		} else if bundle := order.Bundle(); bundle != nil {
			//log.Debug("buildBlock considering bundle", "egp", bundle.MevGasPrice.String(), "hash", bundle.OriginalBundle.Hash)
			err := envDiff.commitBundle(bundle, b.chainData, b.interrupt, false)
			orders.Pop()
			if err != nil {
				log.Trace("Could not apply bundle", "bundle", bundle.OriginalBundle.Hash, "err", err)
				continue
			}

			log.Trace("Included bundle", "bundleEGP", bundle.MevGasPrice.String(), "gasUsed", bundle.TotalGasUsed, "ethToCoinbase", ethIntToFloat(bundle.TotalEth))
			usedBundles = append(usedBundles, *bundle)
		} else if sbundle := order.SBundle(); sbundle != nil {
			usedEntry := types.UsedSBundle{
				Bundle: sbundle.Bundle,
			}
			err := envDiff.commitSBundle(sbundle, b.chainData, b.interrupt, b.builderKey, false)
			orders.Pop()
			if err != nil {
				log.Trace("Could not apply sbundle", "bundle", sbundle.Bundle.Hash(), "err", err)
				usedEntry.Success = false
				usedSbundles = append(usedSbundles, usedEntry)
				continue
			}

			log.Trace("Included sbundle", "bundleEGP", sbundle.MevGasPrice.String(), "ethToCoinbase", ethIntToFloat(sbundle.Profit))
			usedEntry.Success = true
			usedSbundles = append(usedSbundles, usedEntry)
		}
	}

	return usedBundles, usedSbundles
}

func (b *greedyBuilder) mergeOrdersIntoEnvDiff(
	envDiff *environmentDiff, orders *types.TransactionsByPriceAndNonce) ([]types.SimulatedBundle, []types.UsedSBundle) {
	switch b.algoType {
	case ALGO_GREEDY_BUCKETS:
		return b.mergeGreedyBuckets(envDiff, orders)
	case ALGO_GREEDY:
		fallthrough
	default:
		return b.mergeGreedy(envDiff, orders)
	}
}

func (b *greedyBuilder) buildBlock(simBundles []types.SimulatedBundle, simSBundles []*types.SimSBundle, transactions map[common.Address]types.Transactions) (*environment, []types.SimulatedBundle, []types.UsedSBundle) {
	orders := types.NewTransactionsByPriceAndNonce(b.inputEnvironment.signer, transactions, simBundles, simSBundles, b.inputEnvironment.header.BaseFee)
	envDiff := newEnvironmentDiff(b.inputEnvironment.copy())
	usedBundles, usedSbundles := b.mergeOrdersIntoEnvDiff(envDiff, orders)
	envDiff.applyToBaseEnv()
	return envDiff.baseEnvironment, usedBundles, usedSbundles
}
