package miner

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/tracers/logger"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
)

const (
	shiftTx = 1
	popTx   = 2
)

var emptyCodeHash = common.HexToHash("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")

var errInterrupt = errors.New("miner worker interrupted")

type chainData struct {
	chainConfig *params.ChainConfig
	chain       *core.BlockChain
	blacklist   map[common.Address]struct{}
}

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
		baseEnvironment: e.baseEnvironment.copy(),
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
	env.state.StopPrefetcher()
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
func applyTransactionWithBlacklist(signer types.Signer, config *params.ChainConfig, bc core.ChainContext, author *common.Address, gp *core.GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64, cfg vm.Config, blacklist map[common.Address]struct{}) (*types.Receipt, *state.StateDB, error) {
	// short circuit if blacklist is empty
	if len(blacklist) == 0 {
		snap := statedb.Snapshot()
		receipt, err := core.ApplyTransaction(config, bc, author, gp, statedb, header, tx, usedGas, cfg, nil)
		if err != nil {
			statedb.RevertToSnapshot(snap)
		}
		return receipt, statedb, err
	}

	sender, err := types.Sender(signer, tx)
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

	hook := func() error {
		for _, address := range touchTracer.TouchedAddresses() {
			if _, in := blacklist[address]; in {
				return errors.New("blacklist violation, tx trace")
			}
		}
		return nil
	}

	usedGasTmp := *usedGas
	gasPoolTmp := new(core.GasPool).AddGas(gp.Gas())
	snap := statedb.Snapshot()

	receipt, err := core.ApplyTransaction(config, bc, author, gasPoolTmp, statedb, header, tx, &usedGasTmp, cfg, hook)
	if err != nil {
		statedb.RevertToSnapshot(snap)
		return receipt, statedb, err
	}

	*usedGas = usedGasTmp
	*gp = *gasPoolTmp
	return receipt, statedb, err
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

	envDiff.state.SetTxContext(tx.Hash(), envDiff.baseEnvironment.tcount+len(envDiff.newTxs))

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
			log.Trace("Transaction failed, account skipped", "hash", tx.Hash(), "err", err)
			return nil, shiftTx, err
		}
	}

	envDiff.newProfit = envDiff.newProfit.Add(envDiff.newProfit, gasPrice.Mul(gasPrice, big.NewInt(int64(receipt.GasUsed))))
	envDiff.newTxs = append(envDiff.newTxs, tx)
	envDiff.newReceipts = append(envDiff.newReceipts, receipt)
	return receipt, shiftTx, nil
}

// Commit Bundle to env diff
func (envDiff *environmentDiff) commitBundle(bundle *types.SimulatedBundle, chData chainData, interrupt *int32, enforceProfit bool) error {
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
			log.Trace("Bundle tx error", "bundle", bundle.OriginalBundle.Hash, "tx", tx.Hash(), "err", err)
			return err
		}

		if receipt.Status != types.ReceiptStatusSuccessful && !bundle.OriginalBundle.RevertingHash(tx.Hash()) {
			log.Trace("Bundle tx failed", "bundle", bundle.OriginalBundle.Hash, "tx", tx.Hash(), "err", err)
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
	bundleActualEffGP.Mul(bundleActualEffGP, common.Big100)
	bundleSimEffGP.Mul(bundleSimEffGP, big.NewInt(99))

	if bundleSimEffGP.Cmp(bundleActualEffGP) == 1 {
		log.Trace("Bundle underpays after inclusion", "bundle", bundle.OriginalBundle.Hash)
		return errors.New("bundle underpays")
	}

	if enforceProfit {
		// if profit is enforced between simulation and actual commit, only allow >-1% divergence
		simulatedBundleProfit := bundle.TotalEth
		actualBundleProfit := bundleProfit

		// We want to make simulated profit smaller to allow for some leeway in cases where the actual profit is
		// lower due to transaction ordering
		simulatedBundleProfit.Mul(simulatedBundleProfit, big.NewInt(99))
		actualBundleProfit.Mul(actualBundleProfit, common.Big100)

		if simulatedBundleProfit.Cmp(actualBundleProfit) == 1 {
			log.Trace("Lower bundle profit found after inclusion", "bundle", bundle.OriginalBundle.Hash)
			return errors.New("bundle profit too low")
		}
	}

	*envDiff = *tmpEnvDiff
	return nil
}

func estimatePayoutTxGas(env *environment, sender, receiver common.Address, prv *ecdsa.PrivateKey, chData chainData) (uint64, bool, error) {
	if codeHash := env.state.GetCodeHash(receiver); codeHash == (common.Hash{}) || codeHash == emptyCodeHash {
		return params.TxGas, true, nil
	}
	gasLimit := env.gasPool.Gas()

	balance := new(big.Int).SetBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	value := new(big.Int).SetBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})

	diff := newEnvironmentDiff(env)
	diff.state.SetBalance(sender, balance)
	receipt, err := diff.commitPayoutTx(value, sender, receiver, gasLimit, prv, chData)
	if err != nil {
		return 0, false, err
	}
	return receipt.GasUsed, false, nil
}

func applyPayoutTx(envDiff *environmentDiff, sender, receiver common.Address, gas uint64, amountWithFees *big.Int, prv *ecdsa.PrivateKey, chData chainData) (*types.Receipt, error) {
	amount := new(big.Int).Sub(amountWithFees, new(big.Int).Mul(envDiff.header.BaseFee, big.NewInt(int64(gas))))

	if amount.Sign() < 0 {
		return nil, errors.New("not enough funds available")
	}
	rec, err := envDiff.commitPayoutTx(amount, sender, receiver, gas, prv, chData)
	if err != nil {
		return nil, fmt.Errorf("failed to commit payment tx: %w", err)
	} else if rec.Status != types.ReceiptStatusSuccessful {
		return nil, fmt.Errorf("payment tx failed")
	}
	return rec, nil
}

func insertPayoutTx(env *environment, sender, receiver common.Address, gas uint64, isEOA bool, availableFunds *big.Int, prv *ecdsa.PrivateKey, chData chainData) (*types.Receipt, error) {
	if isEOA {
		diff := newEnvironmentDiff(env)
		rec, err := applyPayoutTx(diff, sender, receiver, gas, availableFunds, prv, chData)
		if err != nil {
			return nil, err
		}
		diff.applyToBaseEnv()
		return rec, nil
	}

	var err error
	for i := 0; i < 6; i++ {
		diff := newEnvironmentDiff(env)
		var rec *types.Receipt
		rec, err = applyPayoutTx(diff, sender, receiver, gas, availableFunds, prv, chData)
		if err != nil {
			gas += 1000
			continue
		}

		if gas == rec.GasUsed {
			diff.applyToBaseEnv()
			return rec, nil
		}

		exactEnvDiff := newEnvironmentDiff(env)
		exactRec, err := applyPayoutTx(exactEnvDiff, sender, receiver, rec.GasUsed, availableFunds, prv, chData)
		if err != nil {
			diff.applyToBaseEnv()
			return rec, nil
		}
		exactEnvDiff.applyToBaseEnv()
		return exactRec, nil
	}

	if err == nil {
		return nil, errors.New("could not estimate gas")
	}

	return nil, err
}

func (envDiff *environmentDiff) commitPayoutTx(amount *big.Int, sender, receiver common.Address, gas uint64, prv *ecdsa.PrivateKey, chData chainData) (*types.Receipt, error) {
	senderBalance := envDiff.state.GetBalance(sender)

	if gas < params.TxGas {
		return nil, errors.New("not enough gas for intrinsic gas cost")
	}

	requiredBalance := new(big.Int).Mul(envDiff.header.BaseFee, new(big.Int).SetUint64(gas))
	requiredBalance = requiredBalance.Add(requiredBalance, amount)
	if requiredBalance.Cmp(senderBalance) > 0 {
		return nil, errors.New("not enough balance")
	}

	signer := envDiff.baseEnvironment.signer
	tx, err := types.SignNewTx(prv, signer, &types.DynamicFeeTx{
		ChainID:   chData.chainConfig.ChainID,
		Nonce:     envDiff.state.GetNonce(sender),
		GasTipCap: new(big.Int),
		GasFeeCap: envDiff.header.BaseFee,
		Gas:       gas,
		To:        &receiver,
		Value:     amount,
	})
	if err != nil {
		return nil, err
	}

	txSender, err := types.Sender(signer, tx)
	if err != nil {
		return nil, err
	}
	if txSender != sender {
		return nil, errors.New("incorrect sender private key")
	}

	receipt, _, err := envDiff.commitTx(tx, chData)
	if err != nil {
		return nil, err
	}

	return receipt, nil
}

func (envDiff *environmentDiff) commitSBundle(b *types.SimSBundle, chData chainData, interrupt *int32, key *ecdsa.PrivateKey, enforceProfit bool) error {
	if key == nil {
		return errors.New("no private key provided")
	}

	tmpEnvDiff := envDiff.copy()

	coinbaseBefore := tmpEnvDiff.state.GetBalance(tmpEnvDiff.header.Coinbase)
	gasBefore := tmpEnvDiff.gasPool.Gas()

	if err := tmpEnvDiff.commitSBundleInner(b.Bundle, chData, interrupt, key); err != nil {
		return err
	}

	coinbaseAfter := tmpEnvDiff.state.GetBalance(tmpEnvDiff.header.Coinbase)
	gasAfter := tmpEnvDiff.gasPool.Gas()

	coinbaseDelta := new(big.Int).Sub(coinbaseAfter, coinbaseBefore)
	gasDelta := new(big.Int).SetUint64(gasBefore - gasAfter)

	if coinbaseDelta.Cmp(common.Big0) < 0 {
		return errors.New("coinbase balance decreased")
	}

	gotEGP := new(big.Int).Div(coinbaseDelta, gasDelta)
	simEGP := new(big.Int).Set(b.MevGasPrice)

	// allow > 1% difference
	gotEGP = gotEGP.Mul(gotEGP, big.NewInt(101))
	simEGP = simEGP.Mul(simEGP, common.Big100)

	if gotEGP.Cmp(simEGP) < 0 {
		return fmt.Errorf("incorrect EGP: got %d, expected %d", gotEGP, simEGP)
	}

	if enforceProfit {
		// if profit is enforced between simulation and actual commit, only allow >-1% divergence
		simulatedProfit := b.Profit
		actualProfit := coinbaseDelta

		// We want to make simulated profit smaller to allow for some leeway in cases where the actual profit is
		// lower due to transaction ordering
		simulatedProfit.Mul(simulatedProfit, big.NewInt(99))
		actualProfit.Mul(actualProfit, common.Big100)

		if simulatedProfit.Cmp(actualProfit) == 1 {
			log.Trace("Lower sbundle profit found after inclusion", "sbundle", b.Bundle.Hash())
			return errors.New("sbundle profit too low")
		}
	}

	*envDiff = *tmpEnvDiff
	return nil
}

func (envDiff *environmentDiff) commitSBundleInner(b *types.SBundle, chData chainData, interrupt *int32, key *ecdsa.PrivateKey) error {
	// check inclusion
	minBlock := b.Inclusion.BlockNumber
	maxBlock := b.Inclusion.MaxBlockNumber
	if current := envDiff.header.Number.Uint64(); current < minBlock || current > maxBlock {
		return fmt.Errorf("bundle inclusion block number out of range: %d <= %d <= %d", minBlock, current, maxBlock)
	}

	// extract constraints into convenient format
	refundIdx := make([]bool, len(b.Body))
	refundPercents := make([]int, len(b.Body))
	for _, el := range b.Validity.Refund {
		refundIdx[el.BodyIdx] = true
		refundPercents[el.BodyIdx] = el.Percent
	}

	var (
		totalProfit      *big.Int = new(big.Int)
		refundableProfit *big.Int = new(big.Int)
	)

	var (
		coinbaseDelta  = new(big.Int)
		coinbaseBefore *big.Int
	)
	// insert body and check it
	for i, el := range b.Body {
		coinbaseDelta.Set(common.Big0)
		coinbaseBefore = envDiff.state.GetBalance(envDiff.header.Coinbase)

		if el.Tx != nil {
			receipt, _, err := envDiff.commitTx(el.Tx, chData)
			if err != nil {
				return err
			}
			if receipt.Status != types.ReceiptStatusSuccessful && !el.CanRevert {
				return errors.New("tx failed")
			}
		} else if el.Bundle != nil {
			err := envDiff.commitSBundleInner(el.Bundle, chData, interrupt, key)
			if err != nil {
				return err
			}
		} else {
			return errors.New("invalid body element")
		}

		coinbaseDelta.Set(envDiff.state.GetBalance(envDiff.header.Coinbase))
		coinbaseDelta.Sub(coinbaseDelta, coinbaseBefore)

		totalProfit.Add(totalProfit, coinbaseDelta)
		if !refundIdx[i] {
			refundableProfit.Add(refundableProfit, coinbaseDelta)
		}
	}

	// enforce constraints
	coinbaseDelta.Set(common.Big0)
	coinbaseBefore = envDiff.state.GetBalance(envDiff.header.Coinbase)
	for i, el := range refundPercents {
		if !refundIdx[i] {
			continue
		}
		refundConfig, err := types.GetRefundConfig(&b.Body[i], envDiff.baseEnvironment.signer)
		if err != nil {
			return err
		}

		maxPayoutCost := new(big.Int).Set(core.SbundlePayoutMaxCost)
		maxPayoutCost.Mul(maxPayoutCost, big.NewInt(int64(len(refundConfig))))
		maxPayoutCost.Mul(maxPayoutCost, envDiff.header.BaseFee)

		allocatedValue := common.PercentOf(refundableProfit, el)
		allocatedValue.Sub(allocatedValue, maxPayoutCost)

		if allocatedValue.Cmp(common.Big0) < 0 {
			return fmt.Errorf("negative payout")
		}

		for _, refund := range refundConfig {
			refundValue := common.PercentOf(allocatedValue, refund.Percent)
			refundReceiver := refund.Address
			rec, err := envDiff.commitPayoutTx(refundValue, envDiff.header.Coinbase, refundReceiver, core.SbundlePayoutMaxCostInt, key, chData)
			if err != nil {
				return err
			}
			if rec.Status != types.ReceiptStatusSuccessful {
				return fmt.Errorf("refund tx failed")
			}
			log.Trace("Committed kickback", "payout", ethIntToFloat(allocatedValue), "receiver", refundReceiver)
		}
	}
	coinbaseDelta.Set(envDiff.state.GetBalance(envDiff.header.Coinbase))
	coinbaseDelta.Sub(coinbaseDelta, coinbaseBefore)
	totalProfit.Add(totalProfit, coinbaseDelta)

	if totalProfit.Cmp(common.Big0) < 0 {
		return fmt.Errorf("negative profit")
	}
	return nil
}
