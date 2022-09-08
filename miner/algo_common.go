package miner

import (
	"errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/tracers/logger"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"math/big"
	"sync/atomic"
)

const (
	shiftTx = 1
	popTx   = 2
)

var errInterrupt = errors.New("miner worker interrupted")

type environmentDiff struct {
	baseEnvironment *environment
	header          *types.Header
	gasPool         *core.GasPool  // available gas used to pack transactions
	state           *state.StateDB // apply state changes here
	newProfit       *big.Int
	newTxs          []*types.Transaction
	newReceipts     []*types.Receipt
}

func newEnvironmentDiff(env *environment) *environmentDiff {
	gasPool := new(core.GasPool).AddGas(env.gasPool.Gas())
	return &environmentDiff{
		baseEnvironment: env,
		header:          types.CopyHeader(env.header),
		gasPool:         gasPool,
		state:           env.state.Copy(),
		newProfit:       new(big.Int),
	}
}

func (e *environmentDiff) copy() *environmentDiff {
	gasPool := new(core.GasPool).AddGas(e.gasPool.Gas())

	return &environmentDiff{
		baseEnvironment: e.baseEnvironment,
		header:          types.CopyHeader(e.header),
		gasPool:         gasPool,
		state:           e.state.Copy(),
		newProfit:       new(big.Int).Set(e.newProfit),
		newTxs:          e.newTxs[:],
		newReceipts:     e.newReceipts[:],
	}
}

func (e *environmentDiff) applyToBaseEnv() {
	env := e.baseEnvironment
	env.gasPool = new(core.GasPool).AddGas(e.gasPool.Gas())
	env.header = e.header
	env.state = e.state
	env.profit.Add(env.profit, e.newProfit)
	env.tcount += len(e.newTxs)
	env.txs = append(env.txs, e.newTxs...)
	env.receipts = append(env.receipts, e.newReceipts...)
}

func checkInterrupt(i *int32) bool {
	return i != nil && atomic.LoadInt32(i) != commitInterruptNone
}

// Simulate bundle on top of current state without modifying it
// pending txs used to track if bundle tx is part of the mempool
func simulateBundle(env *environment, bundle types.MevBundle, chData chainData, interrupt *int32) (types.SimulatedBundle, error) {
	stateDB := env.state.Copy()
	gasPool := new(core.GasPool).AddGas(env.header.GasLimit)

	var totalGasUsed uint64
	gasFees := big.NewInt(0)
	ethSentToCoinbase := big.NewInt(0)

	for i, tx := range bundle.Txs {
		if checkInterrupt(interrupt) {
			return types.SimulatedBundle{}, errInterrupt
		}

		if env.header.BaseFee != nil && tx.Type() == 2 {
			// Sanity check for extremely large numbers
			if tx.GasFeeCap().BitLen() > 256 {
				return types.SimulatedBundle{}, core.ErrFeeCapVeryHigh
			}
			if tx.GasTipCap().BitLen() > 256 {
				return types.SimulatedBundle{}, core.ErrTipVeryHigh
			}
			// Ensure gasFeeCap is greater than or equal to gasTipCap.
			if tx.GasFeeCapIntCmp(tx.GasTipCap()) < 0 {
				return types.SimulatedBundle{}, core.ErrTipAboveFeeCap
			}
		}

		stateDB.Prepare(tx.Hash(), i+env.tcount)
		coinbaseBalanceBefore := stateDB.GetBalance(env.coinbase)

		var tempGasUsed uint64
		receipt, err := core.ApplyTransaction(chData.chainConfig, chData.chain, &env.coinbase, gasPool, stateDB, env.header, tx, &tempGasUsed, *chData.chain.GetVMConfig())
		if err != nil {
			return types.SimulatedBundle{}, err
		}
		if receipt.Status == types.ReceiptStatusFailed && !containsHash(bundle.RevertingTxHashes, receipt.TxHash) {
			return types.SimulatedBundle{}, errors.New("failed tx")
		}

		totalGasUsed += receipt.GasUsed

		_, err = types.Sender(env.signer, tx)
		if err != nil {
			return types.SimulatedBundle{}, err
		}

		// see NOTE below
		//txInPendingPool := false
		//if accountTxs, ok := pendingTxs[from]; ok {
		//	// check if tx is in pending pool
		//	txNonce := tx.Nonce()
		//
		//	for _, accountTx := range accountTxs {
		//		if accountTx.Nonce() == txNonce {
		//			txInPendingPool = true
		//			break
		//		}
		//	}
		//}

		gasUsed := new(big.Int).SetUint64(receipt.GasUsed)
		gasPrice, err := tx.EffectiveGasTip(env.header.BaseFee)
		if err != nil {
			return types.SimulatedBundle{}, err
		}
		gasFeesTx := gasUsed.Mul(gasUsed, gasPrice)
		coinbaseBalanceAfter := stateDB.GetBalance(env.coinbase)
		coinbaseDelta := big.NewInt(0).Sub(coinbaseBalanceAfter, coinbaseBalanceBefore)
		coinbaseDelta.Sub(coinbaseDelta, gasFeesTx)
		ethSentToCoinbase.Add(ethSentToCoinbase, coinbaseDelta)

		// NOTE - it differs from prod!, if changed - change in commit bundle too
		//if !txInPendingPool {
		//	// If tx is not in pending pool, count the gas fees
		//	gasFees.Add(gasFees, gasFeesTx)
		//}
		gasFees.Add(gasFees, gasFeesTx)
	}

	totalEth := new(big.Int).Add(ethSentToCoinbase, gasFees)

	return types.SimulatedBundle{
		MevGasPrice:       new(big.Int).Div(totalEth, new(big.Int).SetUint64(totalGasUsed)),
		TotalEth:          totalEth,
		EthSentToCoinbase: ethSentToCoinbase,
		TotalGasUsed:      totalGasUsed,
		OriginalBundle:    bundle,
	}, nil
}

func applyTransactionWithBlacklist(signer types.Signer, config *params.ChainConfig, bc core.ChainContext, author *common.Address, gp *core.GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64, cfg vm.Config, blacklist map[common.Address]struct{}) (*types.Receipt, *state.StateDB, error) {
	// short circuit if blacklist is empty
	if len(blacklist) == 0 {
		snap := statedb.Snapshot()
		receipt, err := core.ApplyTransaction(config, bc, author, gp, statedb, header, tx, usedGas, cfg)
		if err != nil {
			statedb.RevertToSnapshot(snap)
		}
		return receipt, statedb, err
	}

	sender, err := signer.Sender(tx)
	if err != nil {
		return nil, statedb, err
	}

	if _, in := blacklist[sender]; in {
		return nil, statedb, errors.New("blacklist violation, tx.sender")
	}

	if to := tx.To(); to != nil {
		if _, in := blacklist[*to]; in {
			return nil, statedb, errors.New("blacklist violation, tx.to")
		}
	}

	touchTracer := logger.NewAccountTouchTracer()
	cfg.Tracer = touchTracer
	cfg.Debug = true

	usedGasTmp := *usedGas
	gasPoolTmp := new(core.GasPool).AddGas(gp.Gas())
	stateCopy := statedb.Copy()
	snap := stateCopy.Snapshot()

	stateCopy.Prepare(tx.Hash(), statedb.TxIndex())
	receipt, err := core.ApplyTransaction(config, bc, author, gasPoolTmp, stateCopy, header, tx, &usedGasTmp, cfg)
	if err != nil {
		stateCopy.RevertToSnapshot(snap)
		*usedGas = usedGasTmp
		*gp = *gasPoolTmp
		return receipt, stateCopy, err
	}

	for _, address := range touchTracer.TouchedAddresses() {
		if _, in := blacklist[address]; in {
			return nil, statedb, errors.New("blacklist violation, tx trace")
		}
	}

	*usedGas = usedGasTmp
	*gp = *gasPoolTmp
	return receipt, stateCopy, nil
}

// commit tx to envDiff
func (envDiff *environmentDiff) commitTx(tx *types.Transaction, chData chainData) (*types.Receipt, int, error) {
	header := envDiff.header
	coinbase := &envDiff.baseEnvironment.coinbase
	signer := envDiff.baseEnvironment.signer

	gasPrice, err := tx.EffectiveGasTip(header.BaseFee)
	if err != nil {
		return nil, shiftTx, err
	}

	envDiff.state.Prepare(tx.Hash(), envDiff.baseEnvironment.tcount+len(envDiff.newTxs))

	receipt, newState, err := applyTransactionWithBlacklist(signer, chData.chainConfig, chData.chain, coinbase,
		envDiff.gasPool, envDiff.state, header, tx, &header.GasUsed, *chData.chain.GetVMConfig(), chData.blacklist)
	envDiff.state = newState
	if err != nil {
		switch {
		case errors.Is(err, core.ErrGasLimitReached):
			// Pop the current out-of-gas transaction without shifting in the next from the account
			from, _ := types.Sender(signer, tx)
			log.Trace("Gas limit exceeded for current block", "sender", from)
			return nil, popTx, err

		case errors.Is(err, core.ErrNonceTooLow):
			// New head notification data race between the transaction pool and miner, shift
			from, _ := types.Sender(signer, tx)
			log.Trace("Skipping transaction with low nonce", "sender", from, "nonce", tx.Nonce())
			return nil, shiftTx, err

		case errors.Is(err, core.ErrNonceTooHigh):
			// Reorg notification data race between the transaction pool and miner, skip account =
			from, _ := types.Sender(signer, tx)
			log.Trace("Skipping account with hight nonce", "sender", from, "nonce", tx.Nonce())
			return nil, popTx, err

		case errors.Is(err, core.ErrTxTypeNotSupported):
			// Pop the unsupported transaction without shifting in the next from the account
			from, _ := types.Sender(signer, tx)
			log.Trace("Skipping unsupported transaction type", "sender", from, "type", tx.Type())
			return nil, popTx, err

		default:
			// Strange error, discard the transaction and get the next in line (note, the
			// nonce-too-high clause will prevent us from executing in vain).
			log.Debug("Transaction failed, account skipped", "hash", tx.Hash(), "err", err)
			return nil, shiftTx, err
		}
	}

	envDiff.newProfit = envDiff.newProfit.Add(envDiff.newProfit, gasPrice.Mul(gasPrice, big.NewInt(int64(receipt.GasUsed))))
	envDiff.newTxs = append(envDiff.newTxs, tx)
	envDiff.newReceipts = append(envDiff.newReceipts, receipt)
	return receipt, shiftTx, nil
}

// Commit Bundle to env diff
func (envDiff *environmentDiff) commitBundle(bundle *types.SimulatedBundle, chData chainData, interrupt *int32) error {
	coinbase := envDiff.baseEnvironment.coinbase
	tmpEnvDiff := envDiff.copy()

	coinbaseBalanceBefore := tmpEnvDiff.state.GetBalance(coinbase)

	profitBefore := new(big.Int).Set(tmpEnvDiff.newProfit)
	var gasUsed uint64

	for _, tx := range bundle.OriginalBundle.Txs {
		if tmpEnvDiff.header.BaseFee != nil && tx.Type() == 2 {
			// Sanity check for extremely large numbers
			if tx.GasFeeCap().BitLen() > 256 {
				return core.ErrFeeCapVeryHigh
			}
			if tx.GasTipCap().BitLen() > 256 {
				return core.ErrTipVeryHigh
			}
			// Ensure gasFeeCap is greater than or equal to gasTipCap.
			if tx.GasFeeCapIntCmp(tx.GasTipCap()) < 0 {
				return core.ErrTipAboveFeeCap
			}
		}

		if tx.Value().Sign() == -1 {
			return core.ErrNegativeValue
		}

		_, err := tx.EffectiveGasTip(envDiff.header.BaseFee)
		if err != nil {
			return err
		}

		_, err = types.Sender(envDiff.baseEnvironment.signer, tx)
		if err != nil {
			return err
		}

		if checkInterrupt(interrupt) {
			return errInterrupt
		}

		receipt, _, err := tmpEnvDiff.commitTx(tx, chData)

		if err != nil {
			log.Debug("Bundle tx error", "bundle", bundle.OriginalBundle.Hash, "tx", tx.Hash(), "err", err)
			return err
		}

		if receipt.Status != types.ReceiptStatusSuccessful && !bundle.OriginalBundle.RevertingHash(tx.Hash()) {
			log.Debug("Bundle tx failed", "bundle", bundle.OriginalBundle.Hash, "tx", tx.Hash(), "err", err)
			return errors.New("bundle tx revert")
		}

		gasUsed += receipt.GasUsed
	}
	coinbaseBalanceAfter := tmpEnvDiff.state.GetBalance(coinbase)
	coinbaseBalanceDelta := new(big.Int).Sub(coinbaseBalanceAfter, coinbaseBalanceBefore)
	tmpEnvDiff.newProfit.Add(profitBefore, coinbaseBalanceDelta)

	bundleProfit := coinbaseBalanceDelta

	bundleActualEffGP := bundleProfit.Div(bundleProfit, big.NewInt(int64(gasUsed)))
	bundleSimEffGP := new(big.Int).Set(bundle.MevGasPrice)

	// allow >-1% divergence
	bundleActualEffGP.Mul(bundleActualEffGP, big.NewInt(100))
	bundleSimEffGP.Mul(bundleSimEffGP, big.NewInt(99))

	if bundleSimEffGP.Cmp(bundleActualEffGP) == 1 {
		log.Debug("Bundle underpays after inclusion", "bundle", bundle.OriginalBundle.Hash)
		return errors.New("bundle underpays")
	}

	*envDiff = *tmpEnvDiff
	return nil
}
