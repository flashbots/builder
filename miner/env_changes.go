package miner

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/holiman/uint256"
)

// envChanges is a helper struct to apply and discard changes to the environment
type envChanges struct {
	env      *environment
	gasPool  *core.GasPool
	usedGas  uint64
	profit   *uint256.Int
	txs      []*types.Transaction
	receipts []*types.Receipt
}

func newEnvChanges(env *environment) (*envChanges, error) {
	if err := env.state.NewMultiTxSnapshot(); err != nil {
		return nil, err
	}

	return &envChanges{
		env:      env,
		gasPool:  new(core.GasPool).AddGas(env.gasPool.Gas()),
		usedGas:  env.header.GasUsed,
		profit:   new(uint256.Int).Set(env.profit),
		txs:      make([]*types.Transaction, 0),
		receipts: make([]*types.Receipt, 0),
	}, nil
}

func (c *envChanges) commitPayoutTx(
	amount *uint256.Int, sender, receiver common.Address,
	gas uint64, prv *ecdsa.PrivateKey, chData chainData,
) (*types.Receipt, error) {
	return commitPayoutTx(PayoutTransactionParams{
		Amount:        amount.ToBig(),
		BaseFee:       c.env.header.BaseFee,
		ChainData:     chData,
		Gas:           gas,
		CommitFn:      c.commitTx,
		Receiver:      receiver,
		Sender:        sender,
		SenderBalance: c.env.state.GetBalance(sender).ToBig(),
		SenderNonce:   c.env.state.GetNonce(sender),
		Signer:        c.env.signer,
		PrivateKey:    prv,
	})
}

func (c *envChanges) commitTx(tx *types.Transaction, chData chainData) (*types.Receipt, int, error) {
	signer := c.env.signer
	from, err := types.Sender(signer, tx)
	if err != nil {
		return nil, popTx, err
	}

	gasPrice, err := tx.EffectiveGasTip(c.env.header.BaseFee)
	if err != nil {
		return nil, shiftTx, err
	}

	c.env.state.SetTxContext(tx.Hash(), c.env.tcount+len(c.txs))
	receipt, _, err := applyTransactionWithBlacklist(signer, chData.chainConfig, chData.chain, &c.env.coinbase, c.gasPool, c.env.state, c.env.header, tx, &c.usedGas, *chData.chain.GetVMConfig(), chData.blacklist)
	if err != nil {
		switch {
		case errors.Is(err, core.ErrGasLimitReached):
			// Pop the current out-of-gas transaction without shifting in the next from the account
			log.Trace("Gas limit exceeded for current block", "sender", from)
			return receipt, popTx, err

		case errors.Is(err, core.ErrNonceTooLow):
			// New head notification data race between the transaction pool and miner, shift
			log.Trace("Skipping transaction with low nonce", "sender", from, "nonce", tx.Nonce())
			return receipt, shiftTx, err

		case errors.Is(err, core.ErrNonceTooHigh):
			// Reorg notification data race between the transaction pool and miner, skip account =
			log.Trace("Skipping account with hight nonce", "sender", from, "nonce", tx.Nonce())
			return receipt, popTx, err

		case errors.Is(err, core.ErrTxTypeNotSupported):
			// Pop the unsupported transaction without shifting in the next from the account
			log.Trace("Skipping unsupported transaction type", "sender", from, "type", tx.Type())
			return receipt, popTx, err

		default:
			// Strange error, discard the transaction and get the next in line (note, the
			// nonce-too-high clause will prevent us from executing in vain).
			log.Trace("Transaction failed, account skipped", "hash", tx.Hash(), "err", err)
			return receipt, shiftTx, err
		}
	}

	c.profit = c.profit.Add(c.profit, new(uint256.Int).Mul(new(uint256.Int).SetUint64(receipt.GasUsed), uint256.MustFromBig(gasPrice)))
	c.txs = append(c.txs, tx)
	c.receipts = append(c.receipts, receipt)

	return receipt, shiftTx, nil
}

func (c *envChanges) commitBundle(bundle *types.SimulatedBundle, chData chainData, algoConf algorithmConfig) error {
	var (
		profitBefore   = new(uint256.Int).Set(c.profit)
		coinbaseBefore = new(uint256.Int).Set(c.env.state.GetBalance(c.env.coinbase))
		gasUsedBefore  = c.usedGas
		gasPoolBefore  = new(core.GasPool).AddGas(c.gasPool.Gas())
		txsBefore      = c.txs[:]
		receiptsBefore = c.receipts[:]
		hasBaseFee     = c.env.header.BaseFee != nil

		bundleErr error
	)

	for _, tx := range bundle.OriginalBundle.Txs {
		txHash := tx.Hash()
		// TODO: Checks for base fee and dynamic fee txs should be moved to the transaction pool,
		//   similar to mev-share bundles. See SBundlesPool.validateTx() for reference.
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

		switch {
		case err != nil:
			isRevertibleTx := bundle.OriginalBundle.RevertingHash(txHash)
			// if drop enabled, and revertible tx has error on commit, we skip the transaction and continue with next one
			if algoConf.DropRevertibleTxOnErr && isRevertibleTx {
				log.Trace("Found error on commit for revertible tx, but discard on err is enabled so skipping.",
					"tx", txHash, "err", err)
			} else {
				bundleErr = err
			}
		case receipt != nil:
			if receipt.Status == types.ReceiptStatusFailed && !bundle.OriginalBundle.RevertingHash(txHash) {
				// if transaction reverted and isn't specified as reverting hash, return error
				log.Trace("Bundle tx failed", "bundle", bundle.OriginalBundle.Hash, "tx", txHash, "err", err)
				bundleErr = errors.New("bundle tx revert")
			}
		case receipt == nil && err == nil:
			// NOTE: The expectation is that a receipt is only nil if an error occurred.
			//  If there is no error but receipt is nil, there is likely a programming error.
			bundleErr = errors.New("invalid receipt when no error occurred")
		}

		if bundleErr != nil {
			break
		}
	}

	if bundleErr != nil {
		c.rollback(gasUsedBefore, gasPoolBefore, profitBefore, txsBefore, receiptsBefore)
		return bundleErr
	}

	if bundle.MevGasPrice == nil {
		c.rollback(gasUsedBefore, gasPoolBefore, profitBefore, txsBefore, receiptsBefore)
		return ErrMevGasPriceNotSet
	}

	var (
		bundleProfit = new(uint256.Int).Sub(c.env.state.GetBalance(c.env.coinbase), coinbaseBefore)
		gasUsed      = c.usedGas - gasUsedBefore

		// EGP = Effective Gas Price (Profit / GasUsed)
		simulatedEGP                    = new(uint256.Int).Set(bundle.MevGasPrice)
		actualEGP                       *uint256.Int
		tolerablePriceDifferencePercent = 1

		simulatedBundleProfit = new(uint256.Int).Set(bundle.TotalEth)
		actualBundleProfit    = new(uint256.Int).Set(bundleProfit)
	)

	if gasUsed == 0 {
		c.rollback(gasUsedBefore, gasPoolBefore, profitBefore, txsBefore, receiptsBefore)
		return errors.New("bundle gas used is 0")
	} else {
		actualEGP = new(uint256.Int).Div(bundleProfit, uint256.NewInt(gasUsed))
	}

	err := ValidateGasPriceAndProfit(algoConf,
		actualEGP, simulatedEGP, tolerablePriceDifferencePercent,
		actualBundleProfit, simulatedBundleProfit,
	)
	if err != nil {
		c.rollback(gasUsedBefore, gasPoolBefore, profitBefore, txsBefore, receiptsBefore)
		return err
	}

	c.profit.Add(profitBefore, bundleProfit)
	return nil
}

func (c *envChanges) CommitSBundle(sbundle *types.SimSBundle, chData chainData, key *ecdsa.PrivateKey, algoConf algorithmConfig) error {
	// TODO: Suggestion for future improvement: instead of checking if key is nil, panic.
	//   Discussed with @Ruteri, see PR#90 for details: https://github.com/flashbots/builder/pull/90#discussion_r1285567550
	if key == nil {
		return errNoPrivateKey
	}

	var (
		coinbaseBefore = new(uint256.Int).Set(c.env.state.GetBalance(c.env.coinbase))
		gasPoolBefore  = new(core.GasPool).AddGas(c.gasPool.Gas())
		gasBefore      = c.usedGas
		txsBefore      = c.txs[:]
		receiptsBefore = c.receipts[:]
		profitBefore   = new(uint256.Int).Set(c.profit)
	)

	if err := c.commitSBundle(sbundle.Bundle, chData, key, algoConf); err != nil {
		c.rollback(gasBefore, gasPoolBefore, profitBefore, txsBefore, receiptsBefore)
		return err
	}

	var (
		coinbaseAfter = c.env.state.GetBalance(c.env.header.Coinbase)
		gasAfter      = c.usedGas

		coinbaseDelta = new(uint256.Int).Sub(coinbaseAfter, coinbaseBefore)
		gasDelta      = new(uint256.Int).SetUint64(gasAfter - gasBefore)
	)
	if coinbaseDelta.Cmp(common.U2560) < 0 {
		c.rollback(gasBefore, gasPoolBefore, profitBefore, txsBefore, receiptsBefore)
		return errors.New("coinbase balance decreased")
	}

	gotEGP := new(uint256.Int).Div(coinbaseDelta, gasDelta)
	simEGP := new(uint256.Int).Set(sbundle.MevGasPrice)

	// allow > 1% difference
	actualEGP := new(uint256.Int).Mul(gotEGP, common.U256100)
	simulatedEGP := new(uint256.Int).Mul(simEGP, uint256.NewInt(99))

	if simulatedEGP.Cmp(actualEGP) > 0 {
		c.rollback(gasBefore, gasPoolBefore, profitBefore, txsBefore, receiptsBefore)
		return &lowProfitError{
			ExpectedEffectiveGasPrice: simEGP,
			ActualEffectiveGasPrice:   gotEGP,
		}
	}

	if algoConf.EnforceProfit {
		// if profit is enforced between simulation and actual commit, only allow >-1% divergence
		simulatedProfit := new(uint256.Int).Set(sbundle.Profit)
		actualProfit := new(uint256.Int).Set(coinbaseDelta)

		// We want to make simulated profit smaller to allow for some leeway in cases where the actual profit is
		// lower due to transaction ordering
		simulatedProfitMultiple := common.PercentOf(simulatedProfit, algoConf.ProfitThresholdPercent)
		actualProfitMultiple := new(uint256.Int).Mul(actualProfit, common.U256100)

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
		totalProfit      *uint256.Int = new(uint256.Int)
		refundableProfit *uint256.Int = new(uint256.Int)

		coinbaseDelta  = new(uint256.Int)
		coinbaseBefore *uint256.Int
	)

	// insert body and check it
	for i, el := range sbundle.Body {
		coinbaseDelta.Set(common.U2560)
		coinbaseBefore = c.env.state.GetBalance(c.env.coinbase)

		if el.Tx != nil {
			receipt, _, err := c.commitTx(el.Tx, chData)
			if err != nil {
				// if drop enabled, and revertible tx has error on commit,
				// we skip the transaction and continue with next one
				if algoConf.DropRevertibleTxOnErr && el.CanRevert {
					log.Trace("Found error on commit for revertible tx, but discard on err is enabled so skipping.",
						"tx", el.Tx.Hash(), "err", err)
					continue
				}
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
	coinbaseDelta.Set(common.U2560)
	coinbaseBefore = c.env.state.GetBalance(c.env.header.Coinbase)
	for i, el := range refundPercents {
		if !refundIdx[i] {
			continue
		}
		refundConfig, err := types.GetRefundConfig(&sbundle.Body[i], c.env.signer)
		if err != nil {
			return err
		}

		maxPayoutCost := new(uint256.Int).Set(core.SbundlePayoutMaxCost)
		maxPayoutCost.Mul(maxPayoutCost, uint256.NewInt(uint64(len(refundConfig))))
		maxPayoutCost.Mul(maxPayoutCost, uint256.MustFromBig(c.env.header.BaseFee))

		allocatedValue := common.PercentOf(refundableProfit, el)
		allocatedValue.Sub(allocatedValue, maxPayoutCost)

		if allocatedValue.Cmp(common.U2560) < 0 {
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

	if totalProfit.Cmp(common.U2560) < 0 {
		return fmt.Errorf("negative profit")
	}
	return nil
}

// discard reverts all changes to the environment - every commit operation must be followed by a discard or apply operation
func (c *envChanges) discard() error {
	return c.env.state.MultiTxSnapshotRevert()
}

// rollback reverts all changes to the environment - whereas apply and discard update the state, rollback only updates the environment
// the intended use is to call rollback after a commit operation has failed
func (c *envChanges) rollback(
	gasUsedBefore uint64, gasPoolBefore *core.GasPool, profitBefore *uint256.Int,
	txsBefore []*types.Transaction, receiptsBefore []*types.Receipt,
) {
	c.usedGas = gasUsedBefore
	c.gasPool = gasPoolBefore
	c.txs = txsBefore
	c.receipts = receiptsBefore
	c.profit.Set(profitBefore)
}

func (c *envChanges) apply() error {
	if err := c.env.state.MultiTxSnapshotCommit(); err != nil {
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
