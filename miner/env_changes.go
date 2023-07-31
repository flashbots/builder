package miner

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/tracers/logger"
	"github.com/ethereum/go-ethereum/log"
)

// envChanges is a helper struct to apply and revert changes to the environment
type envChanges struct {
	env      *environment
	gasPool  *core.GasPool
	usedGas  uint64
	profit   *big.Int
	txs      []*types.Transaction
	receipts []*types.Receipt
}

func newEnvChanges(env *environment) (*envChanges, error) {
	if err := env.state.MultiTxSnapshot(); err != nil {
		return nil, err
	}

	return &envChanges{
		env:      env,
		gasPool:  new(core.GasPool).AddGas(env.gasPool.Gas()),
		usedGas:  env.header.GasUsed,
		profit:   new(big.Int).Set(env.profit),
		txs:      make([]*types.Transaction, 0),
		receipts: make([]*types.Receipt, 0),
	}, nil
}

func (c *envChanges) commitPayoutTx(
	amount *big.Int, sender, receiver common.Address,
	gas uint64, prv *ecdsa.PrivateKey, chData chainData) (*types.Receipt, error) {
	return commitPayoutTx(PayoutTransactionParams{
		Amount:        amount,
		BaseFee:       c.env.header.BaseFee,
		ChainData:     chData,
		Gas:           gas,
		CommitFn:      c.commitTx,
		Receiver:      receiver,
		Sender:        sender,
		SenderBalance: c.env.state.GetBalance(sender),
		SenderNonce:   c.env.state.GetNonce(sender),
		Signer:        c.env.signer,
		PrivateKey:    prv,
	})
}

func (c *envChanges) commitTx(tx *types.Transaction, chData chainData) (*types.Receipt, int, error) {
	var (
		gasPoolBefore  = new(core.GasPool).AddGas(c.gasPool.Gas())
		usedGasBefore  = c.usedGas
		txsBefore      = c.txs[:]
		receiptsBefore = c.receipts[:]
		profitBefore   = new(big.Int).Set(c.profit)
	)
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
	// we set precompile to nil, but they are set in the validation code
	// there will be no difference in the result if precompile is not it the blocklist
	touchTracer := logger.NewAccessListTracer(nil, common.Address{}, common.Address{}, nil)
	cfg.Tracer = touchTracer
	cfg.Debug = true

	c.env.state.SetTxContext(tx.Hash(), c.env.tcount+len(c.txs))
	receipt, err := core.ApplyTransaction(chData.chainConfig, chData.chain, &c.env.coinbase, c.gasPool, c.env.state, c.env.header, tx, &c.usedGas, cfg, nil)
	if err != nil {
		c.rollback(usedGasBefore, gasPoolBefore, profitBefore, txsBefore, receiptsBefore)

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

	for _, accessTuple := range touchTracer.AccessList() {
		if _, in := chData.blacklist[accessTuple.Address]; in {
			c.rollback(usedGasBefore, gasPoolBefore, profitBefore, txsBefore, receiptsBefore)
			return nil, popTx, errors.New("blacklist violation, tx trace")
		}
	}

	c.profit.Add(c.profit, new(big.Int).Mul(new(big.Int).SetUint64(receipt.GasUsed), gasPrice))
	c.txs = append(c.txs, tx)
	c.receipts = append(c.receipts, receipt)

	return receipt, shiftTx, nil
}

func (c *envChanges) commitBundle(bundle *types.SimulatedBundle, chData chainData) error {
	var (
		profitBefore   = new(big.Int).Set(c.profit)
		coinbaseBefore = new(big.Int).Set(c.env.state.GetBalance(c.env.coinbase))
		gasUsedBefore  = c.usedGas
		gasPoolBefore  = new(core.GasPool).AddGas(c.gasPool.Gas())
		txsBefore      = c.txs[:]
		receiptsBefore = c.receipts[:]
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
		c.rollback(gasUsedBefore, gasPoolBefore, profitBefore, txsBefore, receiptsBefore)
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
		c.rollback(gasUsedBefore, gasPoolBefore, profitBefore, txsBefore, receiptsBefore)
		return errors.New("bundle underpays")
	}

	c.profit.Add(profitBefore, bundleProfit)
	return nil
}

func (c *envChanges) CommitSBundle(sbundle *types.SimSBundle, chData chainData, key *ecdsa.PrivateKey, algoConf algorithmConfig) error {
	if key == nil {
		return errNoPrivateKey
	}

	var (
		coinbaseBefore = new(big.Int).Set(c.env.state.GetBalance(c.env.coinbase))
		gasPoolBefore  = new(core.GasPool).AddGas(c.gasPool.Gas())
		gasBefore      = c.usedGas
		txsBefore      = c.txs[:]
		receiptsBefore = c.receipts[:]
		profitBefore   = new(big.Int).Set(c.profit)
	)

	if err := c.commitSBundle(sbundle.Bundle, chData, key, algoConf); err != nil {
		c.rollback(gasBefore, gasPoolBefore, profitBefore, txsBefore, receiptsBefore)
		return err
	}

	var (
		coinbaseAfter = c.env.state.GetBalance(c.env.header.Coinbase)
		gasAfter      = c.usedGas

		coinbaseDelta = new(big.Int).Sub(coinbaseAfter, coinbaseBefore)
		gasDelta      = new(big.Int).SetUint64(gasAfter - gasBefore)
	)
	if coinbaseDelta.Cmp(common.Big0) < 0 {
		c.rollback(gasBefore, gasPoolBefore, profitBefore, txsBefore, receiptsBefore)
		return errors.New("coinbase balance decreased")
	}

	gotEGP := new(big.Int).Div(coinbaseDelta, gasDelta)
	simEGP := new(big.Int).Set(sbundle.MevGasPrice)

	// allow > 1% difference
	actualEGP := new(big.Int).Mul(gotEGP, common.Big100)
	simulatedEGP := new(big.Int).Mul(simEGP, big.NewInt(99))

	if simulatedEGP.Cmp(actualEGP) > 0 {
		c.rollback(gasBefore, gasPoolBefore, profitBefore, txsBefore, receiptsBefore)
		return &lowProfitError{
			ExpectedEffectiveGasPrice: simEGP,
			ActualEffectiveGasPrice:   gotEGP,
		}
	}

	if algoConf.EnforceProfit {
		// if profit is enforced between simulation and actual commit, only allow >-1% divergence
		simulatedProfit := new(big.Int).Set(sbundle.Profit)
		actualProfit := new(big.Int).Set(coinbaseDelta)

		// We want to make simulated profit smaller to allow for some leeway in cases where the actual profit is
		// lower due to transaction ordering
		simulatedProfitMultiple := new(big.Int).Mul(simulatedProfit, algoConf.ProfitThresholdPercent)
		actualProfitMultiple := new(big.Int).Mul(actualProfit, common.Big100)

		if simulatedProfitMultiple.Cmp(actualProfitMultiple) > 0 {
			log.Trace("Lower sbundle profit found after inclusion", "sbundle", sbundle.Bundle.Hash())
			c.rollback(gasBefore, gasPoolBefore, profitBefore, txsBefore, receiptsBefore)
			return &lowProfitError{
				ExpectedProfit: simulatedProfit,
				ActualProfit:   actualProfit,
			}
		}
	}

	return nil
}

func (c *envChanges) commitSBundle(sbundle *types.SBundle, chData chainData, key *ecdsa.PrivateKey, algoConf algorithmConfig) error {
	var (
		// check inclusion
		minBlock = sbundle.Inclusion.BlockNumber
		maxBlock = sbundle.Inclusion.MaxBlockNumber
	)
	if current := c.env.header.Number.Uint64(); current < minBlock || current > maxBlock {
		return fmt.Errorf("bundle inclusion block number out of range: %d <= %d <= %d", minBlock, current, maxBlock)
	}

	var (
		// extract constraints into convenient format
		refundIdx      = make([]bool, len(sbundle.Body))
		refundPercents = make([]int, len(sbundle.Body))
	)
	for _, el := range sbundle.Validity.Refund {
		refundIdx[el.BodyIdx] = true
		refundPercents[el.BodyIdx] = el.Percent
	}

	var (
		totalProfit      *big.Int = new(big.Int)
		refundableProfit *big.Int = new(big.Int)

		coinbaseDelta  = new(big.Int)
		coinbaseBefore *big.Int
	)

	// insert body and check it
	for i, el := range sbundle.Body {
		coinbaseDelta.Set(common.Big0)
		coinbaseBefore = c.env.state.GetBalance(c.env.coinbase)

		if el.Tx != nil {
			receipt, _, err := c.commitTx(el.Tx, chData)
			if err != nil {
				return err
			}
			if receipt.Status != types.ReceiptStatusSuccessful && !el.CanRevert {
				return errors.New("tx failed")
			}
		} else if el.Bundle != nil {
			err := c.commitSBundle(el.Bundle, chData, key, algoConf)
			if err != nil {
				return err
			}
		} else {
			return errors.New("invalid body element")
		}

		coinbaseDelta.Set(c.env.state.GetBalance(c.env.coinbase))
		coinbaseDelta.Sub(coinbaseDelta, coinbaseBefore)

		totalProfit.Add(totalProfit, coinbaseDelta)
		if !refundIdx[i] {
			refundableProfit.Add(refundableProfit, coinbaseDelta)
		}
	}

	// enforce constraints
	coinbaseDelta.Set(common.Big0)
	coinbaseBefore = c.env.state.GetBalance(c.env.header.Coinbase)
	for i, el := range refundPercents {
		if !refundIdx[i] {
			continue
		}
		refundConfig, err := types.GetRefundConfig(&sbundle.Body[i], c.env.signer)
		if err != nil {
			return err
		}

		maxPayoutCost := new(big.Int).Set(core.SbundlePayoutMaxCost)
		maxPayoutCost.Mul(maxPayoutCost, big.NewInt(int64(len(refundConfig))))
		maxPayoutCost.Mul(maxPayoutCost, c.env.header.BaseFee)

		allocatedValue := common.PercentOf(refundableProfit, el)
		allocatedValue.Sub(allocatedValue, maxPayoutCost)

		if allocatedValue.Cmp(common.Big0) < 0 {
			return fmt.Errorf("negative payout")
		}

		for _, refund := range refundConfig {
			refundValue := common.PercentOf(allocatedValue, refund.Percent)
			refundReceiver := refund.Address
			rec, err := c.commitPayoutTx(refundValue, c.env.header.Coinbase, refundReceiver, core.SbundlePayoutMaxCostInt, key, chData)
			if err != nil {
				return err
			}
			if rec.Status != types.ReceiptStatusSuccessful {
				return fmt.Errorf("refund tx failed")
			}
			log.Trace("Committed kickback", "payout", ethIntToFloat(allocatedValue), "receiver", refundReceiver)
		}
	}
	coinbaseDelta.Set(c.env.state.GetBalance(c.env.header.Coinbase))
	coinbaseDelta.Sub(coinbaseDelta, coinbaseBefore)
	totalProfit.Add(totalProfit, coinbaseDelta)

	if totalProfit.Cmp(common.Big0) < 0 {
		return fmt.Errorf("negative profit")
	}
	return nil
}

// revert reverts all changes to the environment - every commit operation must be followed by a revert or apply operation
func (c *envChanges) revert() error {
	return c.env.state.MultiTxSnapshotRevert()
}

func (c *envChanges) rollback(
	gasUsedBefore uint64, gasPoolBefore *core.GasPool, profitBefore *big.Int,
	txsBefore []*types.Transaction, receiptsBefore []*types.Receipt) {
	c.usedGas = gasUsedBefore
	c.gasPool = gasPoolBefore
	c.txs = txsBefore
	c.receipts = receiptsBefore
}

func (c *envChanges) apply() error {
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
