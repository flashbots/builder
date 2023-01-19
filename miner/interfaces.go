package miner

import (
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
)

type Simulator[O types.Order, R types.SimulationResult] interface {
	doSimulate(O) R
}

func Simulate[O types.Order, R types.SimulationResult](s Simulator[O, R], order O) R {
	start := time.Now()
	
	r := s.doSimulate(order)

	bundleTxNumHistogram.Update(int64(order.TxNum()))
	simulationMeter.Mark(1)
	if r.Err() != nil {
		log.Trace("Error simulating bundle", "error", r.Err())
		simulationRevertedMeter.Mark(1)
		failedBundleSimulationTimer.UpdateSince(start)
	} else {
		simulationCommittedMeter.Mark(1)
		successfulBundleSimulationTimer.UpdateSince(start)
	}
	return r
}

// Interface of the Bundle Merging Algorithm
type BlockBuilder[O types.Order, R types.SimulationResult] interface {
	doBuildBlock(inputEnv *environment, bundles []types.MevBundle, transactions map[common.Address]types.Transactions) (*environment, []R) // returns the bundles used in the block
}

// Performs bundle merging, returns used bundles
func BuildBlock[O types.Order, R types.SimulationResult](algo BlockBuilder[O, R], bundles []types.MevBundle, transactions map[common.Address]types.Transactions, inputEnv *environment) (*environment, []R) {
	start := time.Now()

	newEnv, committedOrders := algo.doBuildBlock(inputEnv, bundles, transactions)

	buildBlockTimer.Update(time.Since(start))
	return newEnv, committedOrders
}