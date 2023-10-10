package miner

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
)

// environmentDiff is a helper struct used to apply transactions to a block using a copy of the state at that block
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

func (envDiff *environmentDiff) copy() *environmentDiff {
	gasPool := new(core.GasPool).AddGas(envDiff.gasPool.Gas())

	return &environmentDiff{
		baseEnvironment: envDiff.baseEnvironment.copy(),
		header:          types.CopyHeader(envDiff.header),
		gasPool:         gasPool,
		state:           envDiff.state.Copy(),
		newProfit:       new(big.Int).Set(envDiff.newProfit),
		newTxs:          envDiff.newTxs[:],
		newReceipts:     envDiff.newReceipts[:],
	}
}

func (envDiff *environmentDiff) applyToBaseEnv() {
	env := envDiff.baseEnvironment
	env.gasPool = new(core.GasPool).AddGas(envDiff.gasPool.Gas())
	env.header = envDiff.header
	env.state.StopPrefetcher()
	env.state = envDiff.state
	env.profit.Add(env.profit, envDiff.newProfit)
	env.tcount += len(envDiff.newTxs)
	env.txs = append(env.txs, envDiff.newTxs...)
	env.receipts = append(env.receipts, envDiff.newReceipts...)
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

	envDiff.newProfit = envDiff.newProfit.Add(envDiff.newProfit, gasPrice.Mul(gasPrice, big.NewInt(int64(receipt.GasUsed))))
	envDiff.newTxs = append(envDiff.newTxs, tx)
	envDiff.newReceipts = append(envDiff.newReceipts, receipt)

	return receipt, shiftTx, nil
}

// Commit Bundle to env diff
func (envDiff *environmentDiff) commitBundle(bundle *types.SimulatedBundle, chData chainData, interrupt *int32, algoConf algorithmConfig) error {
	coinbase := envDiff.baseEnvironment.coinbase
	tmpEnvDiff := envDiff.copy()

	coinbaseBalanceBefore := tmpEnvDiff.state.GetBalance(coinbase)

	profitBefore := new(big.Int).Set(tmpEnvDiff.newProfit)
	var gasUsed uint64

	for _, tx := range bundle.OriginalBundle.Txs {
		txHash := tx.Hash()
		if tmpEnvDiff.header.BaseFee != nil && tx.Type() == types.DynamicFeeTxType {
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
			isRevertibleTx := bundle.OriginalBundle.RevertingHash(txHash)
			// if drop enabled, and revertible tx has error on commit, we skip the transaction and continue with next one
			if algoConf.DropRevertibleTxOnErr && isRevertibleTx {
				log.Trace("Found error on commit for revertible tx, but discard on err is enabled so skipping.",
					"tx", txHash, "err", err)
				continue
			}
			log.Trace("Bundle tx error", "bundle", bundle.OriginalBundle.Hash, "tx", txHash, "err", err)
			return err
		}

		if receipt != nil {
			if receipt.Status == types.ReceiptStatusFailed && !bundle.OriginalBundle.RevertingHash(txHash) {
				// if transaction reverted and isn't specified as reverting hash, return error
				log.Trace("Bundle tx failed", "bundle", bundle.OriginalBundle.Hash, "tx", txHash, "err", err)
				return errors.New("bundle tx revert")
			}
		} else {
			// NOTE: The expectation is that a receipt is only nil if an error occurred.
			//  If there is no error but receipt is nil, there is likely a programming error.
			return errors.New("invalid receipt when no error occurred")
		}

		gasUsed += receipt.GasUsed
	}
	coinbaseBalanceAfter := tmpEnvDiff.state.GetBalance(coinbase)
	coinbaseBalanceDelta := new(big.Int).Sub(coinbaseBalanceAfter, coinbaseBalanceBefore)
	tmpEnvDiff.newProfit.Add(profitBefore, coinbaseBalanceDelta)

	if bundle.MevGasPrice == nil {
		return ErrMevGasPriceNotSet
	}

	var (
		bundleProfit = coinbaseBalanceDelta
		// EGP = Effective Gas Price (Profit / GasUsed)
		simulatedEGP                    = new(big.Int).Set(bundle.MevGasPrice)
		actualEGP                       *big.Int
		tolerablePriceDifferencePercent = 1

		simulatedBundleProfit = new(big.Int).Set(bundle.TotalEth)
		actualBundleProfit    = new(big.Int).Set(bundleProfit)
	)

	if gasUsed == 0 {
		return errors.New("bundle gas used is 0")
	} else {
		actualEGP = new(big.Int).Div(bundleProfit, big.NewInt(int64(gasUsed)))
	}

	err := ValidateGasPriceAndProfit(algoConf,
		actualEGP, simulatedEGP, tolerablePriceDifferencePercent,
		actualBundleProfit, simulatedBundleProfit,
	)
	if err != nil {
		return err
	}

	*envDiff = *tmpEnvDiff
	return nil
}

func (envDiff *environmentDiff) commitPayoutTx(amount *big.Int, sender, receiver common.Address, gas uint64, prv *ecdsa.PrivateKey, chData chainData) (*types.Receipt, error) {
	return commitPayoutTx(PayoutTransactionParams{
		Amount:        amount,
		BaseFee:       envDiff.header.BaseFee,
		ChainData:     chData,
		Gas:           gas,
		CommitFn:      envDiff.commitTx,
		Receiver:      receiver,
		Sender:        sender,
		SenderBalance: envDiff.state.GetBalance(sender),
		SenderNonce:   envDiff.state.GetNonce(sender),
		Signer:        envDiff.baseEnvironment.signer,
		PrivateKey:    prv,
	})
}

func (envDiff *environmentDiff) commitSBundle(b *types.SimSBundle, chData chainData, interrupt *int32, key *ecdsa.PrivateKey, algoConf algorithmConfig) error {
	// TODO: Suggestion for future improvement: instead of checking if key is nil, panic.
	//   Discussed with @Ruteri, see PR#90 for details: https://github.com/flashbots/builder/pull/90#discussion_r1285567550
	if key == nil {
		return errNoPrivateKey
	}

	tmpEnvDiff := envDiff.copy()

	coinbaseBefore := tmpEnvDiff.state.GetBalance(tmpEnvDiff.header.Coinbase)
	gasBefore := tmpEnvDiff.gasPool.Gas()

	if err := tmpEnvDiff.commitSBundleInner(b.Bundle, chData, interrupt, key, algoConf); err != nil {
		return err
	}

	coinbaseAfter := tmpEnvDiff.state.GetBalance(tmpEnvDiff.header.Coinbase)
	gasAfter := tmpEnvDiff.gasPool.Gas()

	coinbaseDelta := new(big.Int).Sub(coinbaseAfter, coinbaseBefore)
	gasDelta := new(big.Int).SetUint64(gasBefore - gasAfter)

	if coinbaseDelta.Cmp(common.Big0) < 0 {
		return errors.New("coinbase balance decreased")
	}

	var gotEGP *big.Int
	if gasDelta.Cmp(common.Big0) == 0 {
		gotEGP = new(big.Int).SetUint64(0)
	} else {
		gotEGP = new(big.Int).Div(coinbaseDelta, gasDelta)
	}

	simEGP := new(big.Int).Set(b.MevGasPrice)

	// allow > 1% difference
	actualEGP := new(big.Int).Mul(gotEGP, big.NewInt(101))
	simulatedEGP := new(big.Int).Mul(simEGP, common.Big100)

	if simulatedEGP.Cmp(actualEGP) > 0 {
		return &lowProfitError{
			ExpectedEffectiveGasPrice: simEGP,
			ActualEffectiveGasPrice:   gotEGP,
		}
	}

	if algoConf.EnforceProfit {
		// if profit is enforced between simulation and actual commit, only allow >-1% divergence
		simulatedSbundleProfit := new(big.Int).Set(b.Profit)
		actualSbundleProfit := new(big.Int).Set(coinbaseDelta)

		// We want to make simulated profit smaller to allow for some leeway in cases where the actual profit is
		// lower due to transaction ordering
		simulatedProfitMultiple := common.PercentOf(simulatedSbundleProfit, algoConf.ProfitThresholdPercent)
		actualProfitMultiple := new(big.Int).Mul(actualSbundleProfit, common.Big100)

		if simulatedProfitMultiple.Cmp(actualProfitMultiple) > 0 {
			log.Trace("Lower sbundle profit found after inclusion", "sbundle", b.Bundle.Hash())
			return &lowProfitError{
				ExpectedProfit: simulatedSbundleProfit,
				ActualProfit:   actualSbundleProfit,
			}
		}
	}

	*envDiff = *tmpEnvDiff
	return nil
}

func (envDiff *environmentDiff) commitSBundleInner(b *types.SBundle, chData chainData, interrupt *int32, key *ecdsa.PrivateKey, algoConf algorithmConfig) error {
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
			err := envDiff.commitSBundleInner(el.Bundle, chData, interrupt, key, algoConf)
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
