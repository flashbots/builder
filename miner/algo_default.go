package miner

import (
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
)

type GreedyBuilder struct {
	chainData   chainData
	interrupt   *int32
	bundleCache *BundleCache
}

func NewGreedyBuilder(chain *core.BlockChain, chainConfig *params.ChainConfig, blacklist map[common.Address]struct{}, interrupt *int32, bundleCache *BundleCache) *GreedyBuilder {
	return &GreedyBuilder{
		chainData:   chainData{chainConfig, chain, blacklist},
		interrupt:   interrupt,
		bundleCache: bundleCache,
	}
}

func (g *GreedyBuilder) doBuildBlock(inputEnv *environment, orders []types.Order) (*environment, []types.Order) {
	simulator := NewDefaultSimulator(inputEnv, g.chainData.chain, g.chainData.blacklist)
	simulatedOrders, err := g.simulateOrders(inputEnv, orders, simulator)
	if err != nil {
		log.Error("Failed to simulate bundles", "err", err)
	}
	return g.buildBlock(inputEnv, simulatedOrders)
}

func (g *GreedyBuilder) buildBlock(env *environment, orders []types.Order) (*environment, []types.Order) {
	sortedOrders := types.NewOrdersByPriceAndNonce(env.signer, orders, env.header.BaseFee)
	envDiff := newEnvironmentDiff(env)
	usedBundles := g.mergeOrdersIntoEnvDiff(envDiff, sortedOrders)
	envDiff.applyToBaseEnv()
	return envDiff.baseEnvironment, usedBundles
}

func (b *GreedyBuilder) mergeOrdersIntoEnvDiff(envDiff *environmentDiff, orders *types.TransactionsByPriceAndNonce) []types.Order {
	usedBundles := []types.Order{}

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
			err := envDiff.commitBundle(bundle, b.chainData, b.interrupt)
			orders.Pop()
			if err != nil {
				log.Trace("Could not apply bundle", "bundle", bundle.OriginalBundle.Hash, "err", err)
				continue
			}

			log.Trace("Included bundle", "bundleEGP", bundle.MevGasPrice.String(), "gasUsed", bundle.TotalGasUsed, "ethToCoinbase", ethIntToFloat(bundle.TotalEth))
			usedBundles = append(usedBundles, types.SimulatedBundleOrder{Bundle: bundle})
		}
	}

	return usedBundles
}

func (g *GreedyBuilder) simulateOrders(env *environment, orders []types.Order, simulator *DefaultSimulator) ([]types.Order, error) {
	start := time.Now()
	headerHash := env.header.Hash()
	simCache := g.bundleCache.GetBundleCache(headerHash)

	simResult := make([]*simulatedBundle, len(orders))
	bundles := make([]types.MevBundle, 0, len(orders))
	txs := make([]int, 0, len(orders))
	var wg sync.WaitGroup
	for i, order := range orders {
		if order.TxType() == types.Tx {
			txs = append(txs, i)
			continue
		}

		bundle := order.AsBundle()
		if bundle == nil {
			continue
		}

		bundles = append(bundles, *bundle)

		if simmed, ok := simCache.GetSimulatedBundle(bundle.Hash); ok {
			simResult[i] = simmed
			continue
		}

		wg.Add(1)
		go func(idx int, bundle *types.MevBundle) {
			defer wg.Done()

			if len(bundle.Txs) == 0 {
				return
			}

			simmed := Simulate[*types.BundleOrder, *types.SimulatedBundleOrder](simulator, &types.BundleOrder{Bundle: bundle})

			if simmed.Err() != nil {
				log.Trace("Error computing gas for a bundle", "error", simmed.Err())
				return
			}
			simResult[idx] = simmed.AsSimulatedBundle()
		}(i, bundle)
	}

	wg.Wait()

	simCache.UpdateSimulatedBundles(simResult, bundles)

	simulatedOrders := make([]types.Order, 0, len(orders))
	for _, bundle := range simResult {
		if bundle != nil {
			simulatedOrders = append(simulatedOrders, types.SimulatedBundleOrder{Bundle: bundle})
		}
	}

	log.Debug("Simulated bundles", "block", env.header.Number, "allBundles", len(bundles), "okBundles", len(simulatedOrders), "time", time.Since(start))

	for _, txIdx := range txs {
		simulatedOrders = append(simulatedOrders, orders[txIdx])
	}

	return simulatedOrders, nil
}
