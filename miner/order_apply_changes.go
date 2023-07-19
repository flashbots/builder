package miner

import (
	"errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/tracers/logger"
	"github.com/ethereum/go-ethereum/log"
	"math/big"
)

// orderApplyChanges is a helper struct to apply and revert changes to the environment
type orderApplyChanges struct {
	env      *environment
	gasPool  *core.GasPool
	usedGas  uint64
	profit   *big.Int
	txs      []*types.Transaction
	receipts []*types.Receipt
}

func newOrderApplyChanges(env *environment) (*orderApplyChanges, error) {
	if err := env.state.MultiTxSnapshot(); err != nil {
		return nil, err
	}

	return &orderApplyChanges{
		env:      env,
		gasPool:  new(core.GasPool).AddGas(env.gasPool.Gas()),
		usedGas:  env.header.GasUsed,
		profit:   new(big.Int).Set(env.profit),
		txs:      make([]*types.Transaction, 0),
		receipts: make([]*types.Receipt, 0),
	}, nil
}

func (c *orderApplyChanges) commitTx(tx *types.Transaction, chData chainData) (*types.Receipt, int, error) {
	signer := c.env.signer
	sender, err := types.Sender(signer, tx)
	if err != nil {
		return nil, popTx, err
	}

	gasPrice, err := tx.EffectiveGasTip(c.env.header.BaseFee)
	if err != nil {
		return nil, shiftTx, err
	}

	if _, in := chData.blacklist[sender]; in {
		return nil, popTx, errors.New("blacklist violation, tx.sender")
	}

	if to := tx.To(); to != nil {
		if _, in := chData.blacklist[*to]; in {
			return nil, popTx, errors.New("blacklist violation, tx.to")
		}
	}

	cfg := *chData.chain.GetVMConfig()
	touchTracer := logger.NewAccountTouchTracer()
	cfg.Tracer = touchTracer
	cfg.Debug = true

	c.env.state.SetTxContext(tx.Hash(), c.env.tcount+len(c.txs))
	receipt, err := core.ApplyTransaction(chData.chainConfig, chData.chain, &c.env.coinbase, c.gasPool, c.env.state, c.env.header, tx, &c.usedGas, cfg, nil)
	if err != nil {
		switch {
		case errors.Is(err, core.ErrGasLimitReached):
			// Pop the current out-of-gas transaction without shifting in the next from the account
			from, _ := types.Sender(signer, tx)
			log.Trace("Gas limit exceeded for current block", "sender", from)
			return receipt, popTx, err

		case errors.Is(err, core.ErrNonceTooLow):
			// New head notification data race between the transaction pool and miner, shift
			from, _ := types.Sender(signer, tx)
			log.Trace("Skipping transaction with low nonce", "sender", from, "nonce", tx.Nonce())
			return receipt, shiftTx, err

		case errors.Is(err, core.ErrNonceTooHigh):
			// Reorg notification data race between the transaction pool and miner, skip account =
			from, _ := types.Sender(signer, tx)
			log.Trace("Skipping account with hight nonce", "sender", from, "nonce", tx.Nonce())
			return receipt, popTx, err

		case errors.Is(err, core.ErrTxTypeNotSupported):
			// Pop the unsupported transaction without shifting in the next from the account
			from, _ := types.Sender(signer, tx)
			log.Trace("Skipping unsupported transaction type", "sender", from, "type", tx.Type())
			return receipt, popTx, err

		default:
			// Strange error, discard the transaction and get the next in line (note, the
			// nonce-too-high clause will prevent us from executing in vain).
			log.Trace("Transaction failed, account skipped", "hash", tx.Hash(), "err", err)
			return receipt, shiftTx, err
		}
	}

	for _, address := range touchTracer.TouchedAddresses() {
		if _, in := chData.blacklist[address]; in {
			return nil, popTx, errors.New("blacklist violation, tx trace")
		}
	}

	c.profit.Add(c.profit, new(big.Int).Mul(new(big.Int).SetUint64(receipt.GasUsed), gasPrice))
	c.txs = append(c.txs, tx)
	c.receipts = append(c.receipts, receipt)

	return receipt, shiftTx, nil
}

func (c *orderApplyChanges) commitBundle(bundle *types.SimulatedBundle, chData chainData) error {
	var (
		profitBefore   = new(big.Int).Set(c.profit)
		coinbaseBefore = new(big.Int).Set(c.env.state.GetBalance(c.env.coinbase))
		gasUsedBefore  = c.usedGas
		hasBaseFee     = c.env.header.BaseFee != nil

		bundleErr error
	)

	for _, tx := range bundle.OriginalBundle.Txs {
		if hasBaseFee && tx.Type() == types.DynamicFeeTxType {
			// Sanity check for extremely large numbers
			if tx.GasFeeCap().BitLen() > 256 {
				bundleErr = core.ErrFeeCapVeryHigh
				break
			}
			if tx.GasTipCap().BitLen() > 256 {
				bundleErr = core.ErrTipVeryHigh
				break
			}

			// Ensure gasFeeCap is greater than or equal to gasTipCap.
			if tx.GasFeeCapIntCmp(tx.GasTipCap()) < 0 {
				bundleErr = core.ErrTipAboveFeeCap
				break
			}
		}
		receipt, _, err := c.commitTx(tx, chData)

		if err != nil {
			log.Trace("Bundle tx error", "bundle", bundle.OriginalBundle.Hash, "tx", tx.Hash(), "err", err)
			bundleErr = err
			break
		}

		if receipt.Status != types.ReceiptStatusSuccessful && !bundle.OriginalBundle.RevertingHash(tx.Hash()) {
			log.Trace("Bundle tx failed", "bundle", bundle.OriginalBundle.Hash, "tx", tx.Hash(), "err", err)
			bundleErr = errors.New("bundle tx revert")
			break
		}
	}

	if bundleErr != nil {
		return bundleErr
	}

	var (
		bundleProfit = new(big.Int).Sub(c.env.state.GetBalance(c.env.coinbase), coinbaseBefore)
		gasUsed      = c.usedGas - gasUsedBefore

		effGP    = new(big.Int).Div(bundleProfit, new(big.Int).SetUint64(gasUsed))
		simEffGP = new(big.Int).Set(bundle.MevGasPrice)
	)

	// allow >-1% divergence
	effGP.Mul(effGP, common.Big100)
	simEffGP.Mul(simEffGP, big.NewInt(99))
	if simEffGP.Cmp(effGP) > 0 {
		log.Trace("Bundle underpays after inclusion", "bundle", bundle.OriginalBundle.Hash)
		return errors.New("bundle underpays")
	}

	c.profit.Add(profitBefore, bundleProfit)
	return nil
}

// revert reverts all changes to the environment - every commit operation must be followed by a revert or apply operation
func (c *orderApplyChanges) revert() error {
	return c.env.state.MultiTxSnapshotRevert()
}

func (c *orderApplyChanges) apply() error {
	if err := c.env.state.MultiTxSnapshotDiscard(); err != nil {
		return err
	}

	c.env.gasPool.SetGas(c.gasPool.Gas())
	c.env.header.GasUsed = c.usedGas
	c.env.profit.Set(c.profit)
	c.env.tcount += len(c.txs)
	c.env.txs = append(c.env.txs, c.txs...)
	c.env.receipts = append(c.env.receipts, c.receipts...)
	return nil
}
