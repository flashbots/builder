package miner

import (
	"crypto/ecdsa"
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
type greedyMultiSnapBuilder struct {
	inputEnvironment *environment
	chainData        chainData
	builderKey       *ecdsa.PrivateKey
	interrupt        *atomic.Int32
	algoConf         algorithmConfig
}

func newGreedyMultiSnapBuilder(
	chain *core.BlockChain, chainConfig *params.ChainConfig, algoConf *algorithmConfig,
	blacklist map[common.Address]struct{}, env *environment, key *ecdsa.PrivateKey, interrupt *atomic.Int32,
) *greedyMultiSnapBuilder {
	if algoConf == nil {
		algoConf = &defaultAlgorithmConfig
	}
	return &greedyMultiSnapBuilder{
		inputEnvironment: env,
		chainData:        chainData{chainConfig, chain, blacklist},
		builderKey:       key,
		interrupt:        interrupt,
		algoConf:         *algoConf,
	}
}

func (b *greedyMultiSnapBuilder) buildBlock(simBundles []types.SimulatedBundle, simSBundles []*types.SimSBundle, transactions map[common.Address][]*txpool.LazyTransaction) (*environment, []types.SimulatedBundle, []types.UsedSBundle) {
	orders := newTransactionsByPriceAndNonce(b.inputEnvironment.signer, transactions, simBundles, simSBundles, b.inputEnvironment.header.BaseFee)

	var (
		usedBundles  []types.SimulatedBundle
		usedSbundles []types.UsedSBundle
	)

	changes, err := newEnvChanges(b.inputEnvironment)
	if err != nil {
		log.Error("Failed to create new environment changes", "err", err)
		return b.inputEnvironment, usedBundles, usedSbundles
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
			if tx.Resolve() == nil {
				log.Trace("Ignoring evicted transaction", "hash", tx.Hash)
				orders.Pop()
				continue
			}
			receipt, skip, err := changes.commitTx(tx.Tx, b.chainData)
			switch skip {
			case shiftTx:
				orders.Shift()
			case popTx:
				orders.Pop()
			}
			orderFailed = err != nil

			if err != nil {
				log.Trace("could not apply tx", "hash", tx.Hash, "err", err)
			} else {
				// we don't check for error here because if EGP returns error, it would have been caught and returned by commitTx
				effGapPrice, _ := tx.Tx.EffectiveGasTip(changes.env.header.BaseFee)
				log.Trace("Included tx", "EGP", effGapPrice.String(), "gasUsed", receipt.GasUsed)
			}
		} else if bundle := order.Bundle(); bundle != nil {
			err := changes.commitBundle(bundle, b.chainData, b.algoConf)
			orders.Pop()
			orderFailed = err != nil

			if err != nil {
				log.Trace("Could not apply bundle", "bundle", bundle.OriginalBundle.Hash, "err", err)
			} else {
				log.Trace("Included bundle", "bundleEGP", bundle.MevGasPrice.String(),
					"gasUsed", bundle.TotalGasUsed, "ethToCoinbase", ethIntToFloat(bundle.EthSentToCoinbase))
				usedBundles = append(usedBundles, *bundle)
			}
		} else if sbundle := order.SBundle(); sbundle != nil {
			err := changes.CommitSBundle(sbundle, b.chainData, b.builderKey, b.algoConf)
			orders.Pop()
			orderFailed = err != nil
			usedEntry := types.UsedSBundle{
				Bundle:  sbundle.Bundle,
				Success: err == nil,
			}

			if err != nil {
				log.Trace("Could not apply sbundle", "bundle", sbundle.Bundle.Hash(), "err", err)
			} else {
				log.Trace("Included sbundle", "bundleEGP", sbundle.MevGasPrice.String(), "ethToCoinbase", ethIntToFloat(sbundle.Profit))
			}

			usedSbundles = append(usedSbundles, usedEntry)
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
