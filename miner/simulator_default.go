package miner

import (
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/tracers/logger"
)


type DefaultSimulator struct {
	baseEnvironment *environment
	header          *types.Header
	chain           *core.BlockChain
	blockList       map[common.Address]struct{}
}

func NewDefaultSimulator(env *environment, chain *core.BlockChain, blockList map[common.Address]struct{}) *DefaultSimulator {
	return &DefaultSimulator{
		baseEnvironment: env,
		header:          types.CopyHeader(env.header),
		chain:           chain,
		blockList:       blockList,
	}
}

func (s *DefaultSimulator) doSimulate(bundle *types.MevBundle) *types.SimulatedBundle {
	if len(bundle.Txs) == 0 {
		return &simulatedBundle{}
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
				return &simulatedBundle{Error: core.ErrFeeCapVeryHigh}
			}
			if tx.GasTipCap().BitLen() > 256 {
				return &simulatedBundle{Error: core.ErrTipVeryHigh}
			}
			// Ensure gasFeeCap is greater than or equal to gasTipCap.
			if tx.GasFeeCapIntCmp(tx.GasTipCap()) < 0 {
				return &simulatedBundle{Error: core.ErrTipAboveFeeCap}
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
			return &simulatedBundle{Error: err}
		}
		if receipt.Status == types.ReceiptStatusFailed && !containsHash(bundle.RevertingTxHashes, receipt.TxHash) {
			return &simulatedBundle{Error: errors.New("failed tx")}
		}
		if len(s.blockList) != 0 {
			for _, address := range tracer.TouchedAddresses() {
				if _, in := s.blockList[address]; in {
					return &simulatedBundle{Error: errBlocklistViolation}
				}
			}
		}

		totalGasUsed += receipt.GasUsed

		_, err = types.Sender(env.signer, tx)
		if err != nil {
			return &simulatedBundle{Error: err}
		}

		gasUsed := new(big.Int).SetUint64(receipt.GasUsed)
		gasPrice, err := tx.EffectiveGasTip(env.header.BaseFee)
		if err != nil {
			return &simulatedBundle{Error: err}
		}
		gasFeesTx := gasUsed.Mul(gasUsed, gasPrice)
		coinbaseBalanceAfter := state.GetBalance(env.coinbase)
		coinbaseDelta := big.NewInt(0).Sub(coinbaseBalanceAfter, coinbaseBalanceBefore)
		coinbaseDelta.Sub(coinbaseDelta, gasFeesTx)
		ethSentToCoinbase.Add(ethSentToCoinbase, coinbaseDelta)
	}

	totalEth := new(big.Int).Add(ethSentToCoinbase, gasFees)

	return &simulatedBundle{
		MevGasPrice:       new(big.Int).Div(totalEth, new(big.Int).SetUint64(totalGasUsed)),
		TotalEth:          totalEth,
		EthSentToCoinbase: ethSentToCoinbase,
		TotalGasUsed:      totalGasUsed,
		OriginalBundle:    *bundle,
		Error:             nil,
	}
}

