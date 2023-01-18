package miner

import (
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
)

type Simulator[O types.Order, S types.SimulatedOrder] interface {
	doSimulate(O) S
}

func Simulate[O types.Order, S types.SimulatedOrder](s Simulator[O, S], order O) S {
	start := time.Now()
	
	r := s.doSimulate(order)

	if order.TxType() == types.Bundle {
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
	}
	return r
}

// Interface of the Bundle Merging Algorithm
type BlockBuilder[O types.Order] interface {
	doBuildBlock(inputEnv *environment, orders []O) (*environment, []O) // returns the bundles used in the block
}

// Performs bundle merging, returns results
func BuildBlock[O types.Order](algo BlockBuilder[O], orders []O, inputEnv *environment) (*environment, []O) {
	start := time.Now()

	newEnv, committedOrders := algo.doBuildBlock(inputEnv, orders)

	buildBlockTimer.Update(time.Since(start))
	return newEnv, committedOrders // newEnv returns block profit metric
}