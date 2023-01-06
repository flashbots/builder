package miner

import (
	"errors"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/tracers/logger"
	"github.com/ethereum/go-ethereum/log"
)

type Order interface {
	IsTx() bool
	IsBundle() bool
	TxNum() int
}

type SimulatedOrder interface {
	Err() error
}

type Simulator[O Order, S SimulatedOrder] interface {
	doSimulate(O) S
}

type DefaultSimulator struct {
	baseEnvironment *environment
	header          *types.Header
	gasPool         *core.GasPool  // available gas used to pack transactions
	state           *state.StateDB // apply state changes here
	newProfit       *big.Int
	newTxs          []*types.Transaction
	newReceipts     []*types.Receipt
	chain           *core.BlockChain
	blockList       map[common.Address]struct{}
}

func NewDefaultSimulator(env *environment, chain *core.BlockChain, blockList map[common.Address]struct{}) *DefaultSimulator {
	gasPool := new(core.GasPool).AddGas(env.gasPool.Gas())

	return &DefaultSimulator{
		baseEnvironment: env,
		header:          types.CopyHeader(env.header),
		gasPool:         gasPool,
		state:           env.state.Copy(),
		newProfit:       new(big.Int),
		chain:           chain,
		blockList:       blockList,
	}
}

func (s *DefaultSimulator) copy() *DefaultSimulator {
	gasPool := new(core.GasPool).AddGas(s.gasPool.Gas())

	return &DefaultSimulator{
		baseEnvironment: s.baseEnvironment.copy(),
		header:          types.CopyHeader(s.header),
		gasPool:         gasPool,
		state:           s.state.Copy(),
		newProfit:       new(big.Int).Set(s.newProfit),
		newTxs:          s.newTxs[:],
		newReceipts:     s.newReceipts[:],
	}
}

func (s *DefaultSimulator) applyToBaseEnv() {
	env := s.baseEnvironment
	env.gasPool = new(core.GasPool).AddGas(s.gasPool.Gas())
	env.header = s.header
	env.state.StopPrefetcher()
	env.state = s.state
	env.profit.Add(env.profit, s.newProfit)
	env.tcount += len(s.newTxs)
	env.txs = append(env.txs, s.newTxs...)
	env.receipts = append(env.receipts, s.newReceipts...)
}

func (s *DefaultSimulator) doSimulate(bundle types.MevBundle) types.SimulatedBundle {
	if len(bundle.Txs) == 0 {
		return simulatedBundle{}
	}

	env := s.baseEnvironment
	state := env.state.Copy()
	gasPool := new(core.GasPool).AddGas(env.header.GasLimit)

	var totalGasUsed uint64 = 0
	var tempGasUsed uint64
	gasFees := new(big.Int)

	ethSentToCoinbase := new(big.Int)

	for i, tx := range bundle.Txs {
		if s.header.BaseFee != nil && tx.Type() == 2 {
			// Sanity check for extremely large numbers
			if tx.GasFeeCap().BitLen() > 256 {
				return simulatedBundle{Error: core.ErrFeeCapVeryHigh}
			}
			if tx.GasTipCap().BitLen() > 256 {
				return simulatedBundle{Error: core.ErrTipVeryHigh}
			}
			// Ensure gasFeeCap is greater than or equal to gasTipCap.
			if tx.GasFeeCapIntCmp(tx.GasTipCap()) < 0 {
				return simulatedBundle{Error: core.ErrTipAboveFeeCap}
			}
		}

		state.Prepare(tx.Hash(), i)
		coinbaseBalanceBefore := state.GetBalance(env.coinbase)

		config := *s.chain.GetVMConfig()
		var tracer *logger.AccountTouchTracer
		if len(s.blockList) != 0 {
			tracer = logger.NewAccountTouchTracer()
			config.Tracer = tracer
			config.Debug = true
		}
		receipt, err := core.ApplyTransaction(s.chain.Config(), s.chain, &env.coinbase, gasPool, state, env.header, tx, &tempGasUsed, config, nil)
		if err != nil {
			return simulatedBundle{Error: err}
		}
		if receipt.Status == types.ReceiptStatusFailed && !containsHash(bundle.RevertingTxHashes, receipt.TxHash) {
			return simulatedBundle{Error: errors.New("failed tx")}
		}
		if len(s.blockList) != 0 {
			for _, address := range tracer.TouchedAddresses() {
				if _, in := s.blockList[address]; in {
					return simulatedBundle{Error: errBlocklistViolation}
				}
			}
		}

		totalGasUsed += receipt.GasUsed

		_, err = types.Sender(env.signer, tx)
		if err != nil {
			return simulatedBundle{Error: err}
		}

		gasUsed := new(big.Int).SetUint64(receipt.GasUsed)
		gasPrice, err := tx.EffectiveGasTip(env.header.BaseFee)
		if err != nil {
			return simulatedBundle{Error: err}
		}
		gasFeesTx := gasUsed.Mul(gasUsed, gasPrice)
		coinbaseBalanceAfter := state.GetBalance(env.coinbase)
		coinbaseDelta := big.NewInt(0).Sub(coinbaseBalanceAfter, coinbaseBalanceBefore)
		coinbaseDelta.Sub(coinbaseDelta, gasFeesTx)
		ethSentToCoinbase.Add(ethSentToCoinbase, coinbaseDelta)
	}

	totalEth := new(big.Int).Add(ethSentToCoinbase, gasFees)

	return simulatedBundle{
		MevGasPrice:       new(big.Int).Div(totalEth, new(big.Int).SetUint64(totalGasUsed)),
		TotalEth:          totalEth,
		EthSentToCoinbase: ethSentToCoinbase,
		TotalGasUsed:      totalGasUsed,
		OriginalBundle:    bundle,
		Error:             nil,
	}
}

func Simulate[O Order, S SimulatedOrder](s Simulator[O, S], order O) SimulatedOrder {
	start := time.Now()
	
	r := s.doSimulate(order)

	if order.IsBundle() {
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
