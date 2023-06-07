package core

import (
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
)

var (
	ErrInvalidInclusion = errors.New("invalid inclusion")

	ErrTxFailed       = errors.New("tx failed")
	ErrNegativeProfit = errors.New("negative profit")
	ErrInvalidBundle  = errors.New("invalid bundle")

	SbundlePayoutMaxCostInt uint64 = 30_000
	SbundlePayoutMaxCost           = big.NewInt(30_000)
)

type SimBundleResult struct {
	TotalProfit     *big.Int
	RefundableValue *big.Int
	GasUsed         uint64
	MevGasPrice     *big.Int
	BodyLogs        []SimBundleBodyLogs
}

type SimBundleBodyLogs struct {
	TxLogs     []*types.Log        `json:"txLogs,omitempty"`
	BundleLogs []SimBundleBodyLogs `json:"bundleLogs,omitempty"`
}

func NewSimBundleResult() SimBundleResult {
	return SimBundleResult{
		TotalProfit:     big.NewInt(0),
		RefundableValue: big.NewInt(0),
		GasUsed:         0,
		MevGasPrice:     big.NewInt(0),
		BodyLogs:        nil,
	}
}

// SimBundle simulates a bundle and returns the result
// Arguments are the same as in ApplyTransaction with the same change semantics:
// - statedb is modified
// - header is not modified
// - gp is modified
// - usedGas is modified (by txs that were applied)
// Payout transactions will not be applied to the state.
// GasUsed in return will include the gas that might be used by the payout txs.
func SimBundle(config *params.ChainConfig, bc *BlockChain, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, b *types.SBundle, txIdx int, usedGas *uint64, cfg vm.Config, logs bool) (SimBundleResult, error) {
	res := NewSimBundleResult()

	currBlock := header.Number.Uint64()
	if currBlock < b.Inclusion.BlockNumber || currBlock > b.Inclusion.MaxBlockNumber {
		return res, ErrInvalidInclusion
	}

	// extract constraints into convenient format
	refundIdx := make([]bool, len(b.Body))
	refundPercents := make([]int, len(b.Body))
	for _, el := range b.Validity.Refund {
		refundIdx[el.BodyIdx] = true
		refundPercents[el.BodyIdx] = el.Percent
	}

	var (
		coinbaseDelta  = new(big.Int)
		coinbaseBefore *big.Int
	)
	for i, el := range b.Body {
		coinbaseDelta.Set(common.Big0)
		coinbaseBefore = statedb.GetBalance(header.Coinbase)

		if el.Tx != nil {
			statedb.SetTxContext(el.Tx.Hash(), txIdx)
			txIdx++
			receipt, err := ApplyTransaction(config, bc, author, gp, statedb, header, el.Tx, usedGas, cfg, nil)
			if err != nil {
				return res, err
			}
			if receipt.Status != types.ReceiptStatusSuccessful && !el.CanRevert {
				return res, ErrTxFailed
			}
			res.GasUsed += receipt.GasUsed
			if logs {
				res.BodyLogs = append(res.BodyLogs, SimBundleBodyLogs{TxLogs: receipt.Logs})
			}
		} else if el.Bundle != nil {
			innerRes, err := SimBundle(config, bc, author, gp, statedb, header, el.Bundle, txIdx, usedGas, cfg, logs)
			if err != nil {
				return res, err
			}
			res.GasUsed += innerRes.GasUsed
			if logs {
				res.BodyLogs = append(res.BodyLogs, SimBundleBodyLogs{BundleLogs: innerRes.BodyLogs})
			}
		} else {
			return res, ErrInvalidBundle
		}

		coinbaseDelta.Set(statedb.GetBalance(header.Coinbase))
		coinbaseDelta.Sub(coinbaseDelta, coinbaseBefore)

		res.TotalProfit.Add(res.TotalProfit, coinbaseDelta)
		if !refundIdx[i] {
			res.RefundableValue.Add(res.RefundableValue, coinbaseDelta)
		}
	}

	// estimate payout value and subtract from total profit
	signer := types.MakeSigner(config, header.Number)
	for i, el := range refundPercents {
		if !refundIdx[i] {
			continue
		}
		// we pay tx cost out of the refundable value

		// cost
		refundConfig, err := types.GetRefundConfig(&b.Body[i], signer)
		if err != nil {
			return res, err
		}
		payoutTxFee := new(big.Int).Mul(header.BaseFee, SbundlePayoutMaxCost)
		payoutTxFee.Mul(payoutTxFee, new(big.Int).SetInt64(int64(len(refundConfig))))
		res.GasUsed += SbundlePayoutMaxCost.Uint64() * uint64(len(refundConfig))

		// allocated refundable value
		payoutValue := common.PercentOf(res.RefundableValue, el)

		if payoutTxFee.Cmp(payoutValue) > 0 {
			return res, ErrNegativeProfit
		}

		res.TotalProfit.Sub(res.TotalProfit, payoutValue)
	}

	if res.TotalProfit.Sign() < 0 {
		res.TotalProfit.Set(common.Big0)
		return res, ErrNegativeProfit
	}
	res.MevGasPrice.Div(res.TotalProfit, new(big.Int).SetUint64(res.GasUsed))
	return res, nil
}
