package miner

import (
	"crypto/ecdsa"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"math/big"
	"sort"
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
	interrupt        *int32
}

func newGreedyBucketsBuilder(
	chain *core.BlockChain, chainConfig *params.ChainConfig,
	blacklist map[common.Address]struct{}, env *environment, key *ecdsa.PrivateKey, interrupt *int32,
) *greedyBucketsBuilder {
	return &greedyBucketsBuilder{
		inputEnvironment: env,
		chainData:        chainData{chainConfig: chainConfig, chain: chain, blacklist: blacklist},
		builderKey:       key,
		interrupt:        interrupt,
	}
}

func (b *greedyBucketsBuilder) commit(envDiff *environmentDiff, transactions []*types.TxWithMinerFee, orders *types.TransactionsByPriceAndNonce) ([]types.SimulatedBundle, []types.UsedSBundle) {
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

func (b *greedyBucketsBuilder) mergeOrdersIntoEnvDiff(
	envDiff *environmentDiff, orders *types.TransactionsByPriceAndNonce) ([]types.SimulatedBundle, []types.UsedSBundle) {
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

		SortInPlaceByProfit = func(transactions []*types.TxWithMinerFee) {
			sort.SliceStable(transactions, func(i, j int) bool {
				return transactions[i].Profit().Cmp(transactions[j].Profit()) > 0
			})
		}
	)

	bucket := InitializeBucket(orders.Peek())
	for {
		order := orders.Peek()
		if order == nil {
			if len(transactionBucket) != 0 {
				SortInPlaceByProfit(transactionBucket)
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
				SortInPlaceByProfit(transactionBucket)
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

func (b *greedyBucketsBuilder) buildBlock(simBundles []types.SimulatedBundle, simSBundles []*types.SimSBundle, transactions map[common.Address]types.Transactions) (*environment, []types.SimulatedBundle, []types.UsedSBundle) {
	orders := types.NewTransactionsByPriceAndNonce(b.inputEnvironment.signer, transactions, simBundles, simSBundles, b.inputEnvironment.header.BaseFee)
	envDiff := newEnvironmentDiff(b.inputEnvironment.copy())
	usedBundles, usedSbundles := b.mergeOrdersIntoEnvDiff(envDiff, orders)
	envDiff.applyToBaseEnv()
	return envDiff.baseEnvironment, usedBundles, usedSbundles
}
