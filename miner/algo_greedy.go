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
}

func newGreedyBuilder(chain *core.BlockChain, chainConfig *params.ChainConfig, blacklist map[common.Address]struct{}, env *environment, key *ecdsa.PrivateKey, interrupt *int32) *greedyBuilder {
	return &greedyBuilder{
		inputEnvironment: env,
		chainData:        chainData{chainConfig, chain, blacklist},
		builderKey:       key,
		interrupt:        interrupt,
	}
}

func sortTransactionsByProfit(transactions []*types.TxWithMinerFee) []*types.TxWithMinerFee {
	sort.SliceStable(transactions, func(i, j int) bool {
		if transactions[i].Tx() != nil {
			return false
		}

		if transactions[j].Tx() != nil {
			return false
		}

		var iProfit, jProfit *big.Int
		if iBundle := transactions[i].Bundle(); iBundle != nil {
			iProfit = iBundle.TotalEth
		} else if iSBundle := transactions[i].SBundle(); iSBundle != nil {
			iProfit = iSBundle.Profit
		}

		if jBundle := transactions[j].Bundle(); jBundle != nil {
			jProfit = jBundle.TotalEth
		} else if jSBundle := transactions[j].SBundle(); jSBundle != nil {
			jProfit = jSBundle.Profit
		}

		return iProfit.Cmp(jProfit) > 0
	})

	return transactions
}

func (b *greedyBuilder) commit(envDiff *environmentDiff, transactions []*types.TxWithMinerFee, orders *types.TransactionsByPriceAndNonce) {
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
			err := envDiff.commitBundle(bundle, b.chainData, b.interrupt)
			if err != nil {
				log.Trace("Could not apply bundle", "bundle", bundle.OriginalBundle.Hash, "err", err)
				// TODO: handle retry
				continue
			}

			log.Trace("Included bundle", "bundleEGP", bundle.MevGasPrice.String(), "gasUsed", bundle.TotalGasUsed, "ethToCoinbase", ethIntToFloat(bundle.TotalEth))
			//usedBundles = append(usedBundles, *bundle)
		} else if sbundle := order.SBundle(); sbundle != nil {
			usedEntry := types.UsedSBundle{
				Bundle: sbundle.Bundle,
			}
			err := envDiff.commitSBundle(sbundle, b.chainData, b.interrupt, b.builderKey)
			if err != nil {
				log.Trace("Could not apply sbundle", "bundle", sbundle.Bundle.Hash(), "err", err)
				// TODO: handle retry
				usedEntry.Success = false
				//usedSbundles = append(usedSbundles, usedEntry)
				continue
			}

			log.Trace("Included sbundle", "bundleEGP", sbundle.MevGasPrice.String(), "ethToCoinbase", ethIntToFloat(sbundle.Profit))
			usedEntry.Success = true
			//usedSbundles = append(usedSbundles, usedEntry)
		}
	}
}

func (b *greedyBuilder) mergeGreedyBuckets(envDiff *environmentDiff, orders *types.TransactionsByPriceAndNonce) (
	[]types.SimulatedBundle, []types.UsedSBundle) {
	if orders.Peek() == nil {
		return nil, nil
	}

	var (
		usedBundles       []types.SimulatedBundle
		usedSbundles      []types.UsedSBundle
		transactionBucket []*types.TxWithMinerFee
		basePercent       = new(big.Int).SetUint64(90)
		denominator       = new(big.Int).SetUint64(100)
		percent           = new(big.Int).Div(basePercent, denominator)

		InitializeBucket = func(order *types.TxWithMinerFee) [1]*big.Int {
			bucketMin := new(big.Int).Mul(order.Price(), percent)
			return [1]*big.Int{bucketMin}
		}

		IsOrderInPriceRange = func(order *types.TxWithMinerFee, minPrice *big.Int) bool {
			return order.Price().Cmp(minPrice) > 0
		}
	)

	bucket := InitializeBucket(orders.Peek())
	for {
		order := orders.Peek()
		if order == nil {
			if len(transactionBucket) != 0 {
				transactionBucket = sortTransactionsByProfit(transactionBucket)
				b.commit(envDiff, transactionBucket, orders)
				transactionBucket = nil
				continue // re-run since committing transactions may have pushed higher nonce transactions back into heap
			}
			// TODO: don't break if there are still retryable transactions
			// TODO: need to apply bucketed transactions after heap is empty
			break
		}

		if ok := IsOrderInPriceRange(order, bucket[0]); ok {
			orders.Pop()
			transactionBucket = append(transactionBucket, order)
		} else {
			if len(transactionBucket) != 0 {
				transactionBucket = sortTransactionsByProfit(transactionBucket)
				b.commit(envDiff, transactionBucket, orders)
				transactionBucket = nil
			}
			bucket = InitializeBucket(order)
		}
	}

	return usedBundles, usedSbundles
}

func (b *greedyBuilder) mergeOrdersIntoEnvDiff(envDiff *environmentDiff, orders *types.TransactionsByPriceAndNonce) ([]types.SimulatedBundle, []types.UsedSBundle) {
	usedBundles := []types.SimulatedBundle{}
	usedSbundles := []types.UsedSBundle{}

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
			err := envDiff.commitBundle(bundle, b.chainData, b.interrupt)
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
			err := envDiff.commitSBundle(sbundle, b.chainData, b.interrupt, b.builderKey)
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

func (b *greedyBuilder) buildBlock(simBundles []types.SimulatedBundle, simSBundles []*types.SimSBundle, transactions map[common.Address]types.Transactions) (*environment, []types.SimulatedBundle, []types.UsedSBundle) {
	orders := types.NewTransactionsByPriceAndNonce(b.inputEnvironment.signer, transactions, simBundles, simSBundles, b.inputEnvironment.header.BaseFee)
	envDiff := newEnvironmentDiff(b.inputEnvironment.copy())
	usedBundles, usedSbundles := b.mergeOrdersIntoEnvDiff(envDiff, orders)
	envDiff.applyToBaseEnv()
	return envDiff.baseEnvironment, usedBundles, usedSbundles
}
