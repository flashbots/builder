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
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

const (
	shiftTx = 1
	popTx   = 2
)

const (
	// defaultProfitThresholdPercent is to ensure committed transactions, bundles, sbundles don't fall below this threshold
	// when profit is enforced
	defaultProfitThresholdPercent = 70

	// defaultPriceCutoffPercent is for bucketing transactions by price, used for greedy buckets algorithm
	defaultPriceCutoffPercent = 50
)

var defaultAlgorithmConfig = algorithmConfig{
	DropRevertibleTxOnErr:  false,
	EnforceProfit:          false,
	ExpectedProfit:         nil,
	ProfitThresholdPercent: defaultProfitThresholdPercent,
	PriceCutoffPercent:     defaultPriceCutoffPercent,
}

var emptyCodeHash = common.HexToHash("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")

var (
	ErrMevGasPriceNotSet = errors.New("mev gas price not set")
	errInterrupt         = errors.New("miner worker interrupted")
	errNoPrivateKey      = errors.New("no private key provided")
)

// lowProfitError is returned when an order is not committed due to low profit or low effective gas price
type lowProfitError struct {
	ExpectedProfit *uint256.Int
	ActualProfit   *uint256.Int

	ExpectedEffectiveGasPrice *uint256.Int
	ActualEffectiveGasPrice   *uint256.Int
}

func (e *lowProfitError) Error() string {
	return fmt.Sprintf(
		"low profit: expected %v, actual %v, expected effective gas price %v, actual effective gas price %v",
		e.ExpectedProfit, e.ActualProfit, e.ExpectedEffectiveGasPrice, e.ActualEffectiveGasPrice,
	)
}

type algorithmConfig struct {
	// DropRevertibleTxOnErr is used when a revertible transaction has error on commit, and we wish to discard
	// the transaction and continue processing the rest of a bundle or sbundle.
	// Revertible transactions are specified as hashes that can revert in a bundle or sbundle.
	DropRevertibleTxOnErr bool
	// EnforceProfit is true if we want to enforce a minimum profit threshold
	// for committing a transaction based on ProfitThresholdPercent
	EnforceProfit bool
	// ExpectedProfit should be set on a per-transaction basis when profit is enforced
	ExpectedProfit *big.Int
	// ProfitThresholdPercent is the minimum profit threshold for committing a transaction
	ProfitThresholdPercent int // 0-100, e.g. 70 means 70%
	// PriceCutoffPercent is the minimum effective gas price threshold used for bucketing transactions by price.
	// For example if the top transaction in a list has an effective gas price of 1000 wei and PriceCutoffPercent
	// is 10 (i.e. 10%), then the minimum effective gas price included in the same bucket as the top transaction
	// is (1000 * 10%) = 100 wei.
	PriceCutoffPercent int
}

type chainData struct {
	chainConfig *params.ChainConfig
	chain       *core.BlockChain
	blacklist   map[common.Address]struct{}
}

// PayoutTransactionParams holds parameters for committing a payout transaction, used in commitPayoutTx
type PayoutTransactionParams struct {
	Amount        *big.Int
	BaseFee       *big.Int
	ChainData     chainData
	Gas           uint64
	CommitFn      CommitTxFunc
	Receiver      common.Address
	Sender        common.Address
	SenderBalance *big.Int
	SenderNonce   uint64
	Signer        types.Signer
	PrivateKey    *ecdsa.PrivateKey
}

type (
	// BuildBlockFunc is the function signature for building a block
	BuildBlockFunc func(
		simBundles []types.SimulatedBundle,
		simSBundles []*types.SimSBundle,
		transactions map[common.Address]types.Transactions) (*environment, []types.SimulatedBundle, []types.UsedSBundle)

	// CommitTxFunc is the function signature for committing a transaction
	CommitTxFunc func(*types.Transaction, chainData) (*types.Receipt, int, error)
)

func ValidateGasPriceAndProfit(algoConf algorithmConfig, actualPrice, expectedPrice *uint256.Int, tolerablePriceDifferencePercent int,
	actualProfit, expectedProfit *uint256.Int,
) error {
	// allow tolerablePriceDifferencePercent % divergence
	expectedPriceMultiple := new(uint256.Int).Mul(expectedPrice, uint256.NewInt(100-uint64(tolerablePriceDifferencePercent)))
	actualPriceMultiple := new(uint256.Int).Mul(actualPrice, common.U256100)

	var errLowProfit *lowProfitError = nil
	if expectedPriceMultiple.Cmp(actualPriceMultiple) > 0 {
		errLowProfit = &lowProfitError{
			ExpectedEffectiveGasPrice: expectedPrice,
			ActualEffectiveGasPrice:   actualPrice,
		}
	}

	if algoConf.EnforceProfit {
		// We want to make expected profit smaller to allow for some leeway in cases where the actual profit is
		// lower due to transaction ordering
		expectedProfitMultiple := common.PercentOf(expectedProfit, algoConf.ProfitThresholdPercent)
		actualProfitMultiple := new(uint256.Int).Mul(actualProfit, common.U256100)

		if expectedProfitMultiple.Cmp(actualProfitMultiple) > 0 {
			if errLowProfit == nil {
				errLowProfit = new(lowProfitError)
			}
			errLowProfit.ExpectedProfit = expectedProfit
			errLowProfit.ActualProfit = actualProfit
		}
	}

	if errLowProfit != nil { // staticcheck linter complains if we don't check for nil here
		return errLowProfit
	}
	return nil
}

func checkInterrupt(i *atomic.Int32) bool {
	return i != nil && i.Load() != commitInterruptNone
}

// Simulate bundle on top of current state without modifying it
// pending txs used to track if bundle tx is part of the mempool
func applyTransactionWithBlacklist(
	signer types.Signer, config *params.ChainConfig, bc core.ChainContext, author *common.Address, gp *core.GasPool,
	statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64,
	cfg vm.Config, blacklist map[common.Address]struct{},
) (*types.Receipt, *state.StateDB, error) {
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

	// we set precompile to nil, but they are set in the validation code
	// there will be no difference in the result if precompile is not it the blocklist
	touchTracer := logger.NewAccessListTracer(nil, common.Address{}, common.Address{}, nil)
	cfg.Tracer = touchTracer

	hook := func() error {
		for _, accessTuple := range touchTracer.AccessList() {
			if _, in := blacklist[accessTuple.Address]; in {
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

func estimatePayoutTxGas(env *environment, sender, receiver common.Address, prv *ecdsa.PrivateKey, chData chainData) (uint64, bool, error) {
	if codeHash := env.state.GetCodeHash(receiver); codeHash == (common.Hash{}) || codeHash == emptyCodeHash {
		return params.TxGas, true, nil
	}
	gasLimit := env.gasPool.Gas()

	balance := new(uint256.Int).SetBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
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

func commitPayoutTx(parameters PayoutTransactionParams) (*types.Receipt, error) {
	if parameters.Gas < params.TxGas {
		return nil, errors.New("not enough gas for intrinsic gas cost")
	}

	requiredBalance := new(big.Int).Mul(parameters.BaseFee, new(big.Int).SetUint64(parameters.Gas))
	requiredBalance = requiredBalance.Add(requiredBalance, parameters.Amount)
	if requiredBalance.Cmp(parameters.SenderBalance) > 0 {
		return nil, errors.New("not enough balance")
	}

	tx, err := types.SignNewTx(parameters.PrivateKey, parameters.Signer, &types.DynamicFeeTx{
		ChainID:   parameters.ChainData.chainConfig.ChainID,
		Nonce:     parameters.SenderNonce,
		GasTipCap: new(big.Int),
		GasFeeCap: parameters.BaseFee,
		Gas:       parameters.Gas,
		To:        &parameters.Receiver,
		Value:     parameters.Amount,
	})
	if err != nil {
		return nil, err
	}

	txSender, err := types.Sender(parameters.Signer, tx)
	if err != nil {
		return nil, err
	}

	if txSender != parameters.Sender {
		return nil, errors.New("incorrect sender private key")
	}

	receipt, _, err := parameters.CommitFn(tx, parameters.ChainData)
	return receipt, err
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

// CheckRetryOrderAndReinsert checks if the order has been retried up to the retryLimit and if not, reinserts the order into the orders heap.
func CheckRetryOrderAndReinsert(
	order *txWithMinerFee, orders *transactionsByPriceAndNonce,
	retryMap map[*txWithMinerFee]int, retryLimit int,
) bool {
	var isRetryable bool = false
	if retryCount, exists := retryMap[order]; exists {
		if retryCount != retryLimit {
			isRetryable = true
			retryMap[order] = retryCount + 1
		}
	} else {
		retryMap[order] = 0
		isRetryable = true
	}

	if isRetryable {
		orders.Push(order)
	}

	return isRetryable
}
