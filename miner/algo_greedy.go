package miner

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
)

type chainData struct {
	chainConfig *params.ChainConfig
	chain       *core.BlockChain
	blacklist   map[common.Address]struct{}
}

// / To use it:
// / 1. Copy relevant data from the worker
// / 2. Call buildBlock
// / 2. If new bundles, txs arrive, call buildBlock again
// / This struct lifecycle is tied to 1 block-building task
type greedyBuilder struct {
	inputEnvironment *environment
	chainData        chainData
	interrupt        *int32
}

func newGreedyBuilder(chain *core.BlockChain, chainConfig *params.ChainConfig, blacklist map[common.Address]struct{}, env *environment, interrupt *int32) *greedyBuilder {
	return &greedyBuilder{
		inputEnvironment: env,
		chainData:        chainData{chainConfig, chain, blacklist},
		interrupt:        interrupt,
	}
}

func (b *greedyBuilder) buildBlock(simBundles []types.SimulatedBundle, transactions map[common.Address]types.Transactions) (*environment, []types.SimulatedBundle) {

	env := b.inputEnvironment.copy()

	orders := types.NewTransactionsByPriceAndNonce(env.signer, transactions, simBundles, env.header.BaseFee)
	log.Debug("buildBlock", "totalBundles", len(simBundles))
	for _, bundle := range simBundles {
		log.Debug("buildBlock", "simBHash", bundle.OriginalBundle.Hash)
	}
	envDiff := newEnvironmentDiff(env)

	usedBundles := make([]types.SimulatedBundle, 0)

	for {
		order := orders.Peek()
		if order == nil {
			break
		}

		if order.Tx != nil {
			receipt, skip, err := envDiff.commitTx(order.Tx, b.chainData)
			switch skip {
			case shiftTx:
				orders.Shift()
			case popTx:
				orders.Pop()
			}

			if err != nil {
				log.Info("could not apply tx", "hash", order.Tx.Hash(), "err", err)
				continue
			}
			effGapPrice, err := order.Tx.EffectiveGasTip(env.header.BaseFee)
			if err == nil {
				log.Trace("Included tx", "EGP", effGapPrice.String(), "gasUsed", receipt.GasUsed)
			}
		} else if order.Bundle != nil {
			bundle := order.Bundle
			//log.Debug("buildBlock considering bundle", "egp", bundle.MevGasPrice.String(), "hash", bundle.OriginalBundle.Hash)
			err := envDiff.commitBundle(bundle, b.chainData, b.interrupt)
			orders.Pop()
			if err != nil {
				log.Info("Could not apply bundle", "bundle", bundle.OriginalBundle.Hash, "err", err)
				continue
			}

			log.Info("Included bundle", "bundleEGP", bundle.MevGasPrice.String(), "gasUsed", bundle.TotalGasUsed, "ethToCoinbase", ethIntToFloat(bundle.TotalEth))
			usedBundles = append(usedBundles, *bundle)
		}
	}

	envDiff.applyToBaseEnv()
	return env, usedBundles
}
