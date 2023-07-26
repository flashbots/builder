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

const (
	// defaultProfitPercentMinimum is to ensure committed transactions, bundles, sbundles don't fall below this threshold
	// when profit is enforced
	defaultProfitPercentMinimum = 70

	// defaultPriceCutoffPercent is for bucketing transactions by price, used for greedy buckets algorithm
	defaultPriceCutoffPercent = 50
)

var (
	defaultProfitThreshold = big.NewInt(defaultProfitPercentMinimum)
	defaultAlgorithmConfig = algorithmConfig{
		EnforceProfit:          false,
		ExpectedProfit:         common.Big0,
		ProfitThresholdPercent: defaultProfitThreshold,
		PriceCutoffPercent:     defaultPriceCutoffPercent,
		EnableMultiTxSnap:      false,
	}
)

var emptyCodeHash = common.HexToHash("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")

var (
	errInterrupt         = errors.New("miner worker interrupted")
	errNoAlgorithmConfig = errors.New("no algorithm configuration specified")
	errNoPrivateKey      = errors.New("no private key provided")
)

// lowProfitError is returned when an order is not committed due to low profit or low effective gas price
type lowProfitError struct {
	ExpectedProfit *big.Int
	ActualProfit   *big.Int

	ExpectedEffectiveGasPrice *big.Int
	ActualEffectiveGasPrice   *big.Int
}

func (e *lowProfitError) Error() string {
	return fmt.Sprintf(
		"low profit: expected %v, actual %v, expected effective gas price %v, actual effective gas price %v",
		e.ExpectedProfit, e.ActualProfit, e.ExpectedEffectiveGasPrice, e.ActualEffectiveGasPrice,
	)
}

type (
	algorithmConfig struct {
		// EnforceProfit is true if we want to enforce a minimum profit threshold
		// for committing a transaction based on ProfitThresholdPercent
		EnforceProfit bool
		// ExpectedProfit should be set on a per-transaction basis when profit is enforced
		ExpectedProfit *big.Int
		// ProfitThresholdPercent is the minimum profit threshold for committing a transaction
		ProfitThresholdPercent *big.Int
		// PriceCutoffPercent is the minimum effective gas price threshold used for bucketing transactions by price.
		// For example if the top transaction in a list has an effective gas price of 1000 wei and PriceCutoffPercent
		// is 10 (i.e. 10%), then the minimum effective gas price included in the same bucket as the top transaction
		// is (1000 * 10%) = 100 wei.
		PriceCutoffPercent int
		// EnableMultiTxSnap is true if we want to use multi-transaction snapshot
		// for committing transactions (note: experimental)
		EnableMultiTxSnap bool
	}

	chainData struct {
		chainConfig *params.ChainConfig
		chain       *core.BlockChain
		blacklist   map[common.Address]struct{}
	}

	// BuildBlockFunc is the function signature for building a block
	BuildBlockFunc func(
		simBundles []types.SimulatedBundle,
		simSBundles []*types.SimSBundle,
		transactions map[common.Address]types.Transactions) (*environment, []types.SimulatedBundle, []types.UsedSBundle)

	// CommitTxFunc is the function signature for committing a transaction
	CommitTxFunc func(*types.Transaction, chainData) (*types.Receipt, int, error)

	// PayoutTransactionParams holds parameters for committing a payout transaction, used in commitPayoutTx
	PayoutTransactionParams struct {
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
)

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

	// we set precompile to nil, but they are set in the validation code
	// there will be no difference in the result if precompile is not it the blocklist
	touchTracer := logger.NewAccessListTracer(nil, common.Address{}, common.Address{}, nil)
	cfg.Tracer = touchTracer
	cfg.Debug = true

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

// BuildMultiTxSnapBlock attempts to build a block with input orders using state.MultiTxSnapshot. If a failure occurs attempting to commit a given order,
// it reverts to previous state and the next order is attempted.
func BuildMultiTxSnapBlock(
	inputEnvironment *environment,
	key *ecdsa.PrivateKey,
	chData chainData,
	algoConf algorithmConfig,
	orders *types.TransactionsByPriceAndNonce) ([]types.SimulatedBundle, []types.UsedSBundle, error) {

	var (
		usedBundles      []types.SimulatedBundle
		usedSbundles     []types.UsedSBundle
		orderFailed      = false
		buildBlockErrors []error
	)

	for {
		order := orders.Peek()
		if order == nil {
			break
		}

		orderFailed = false
		changes, err := newEnvChanges(inputEnvironment)
		// if changes cannot be instantiated, return early
		if err != nil {
			log.Error("Failed to create changes", "err", err)
			return nil, nil, err
		}

		// TODO: add support for retry logic
		if tx := order.Tx(); tx != nil {
			_, skip, err := changes.commitTx(tx, chData)
			switch skip {
			case shiftTx:
				orders.Shift()
			case popTx:
				orders.Pop()
			}

			if err != nil {
				buildBlockErrors = append(buildBlockErrors, fmt.Errorf("failed to commit tx: %w", err))
				orderFailed = true
			}
		} else if bundle := order.Bundle(); bundle != nil {
			err = changes.commitBundle(bundle, chData)
			orders.Pop()
			if err != nil {
				buildBlockErrors = append(buildBlockErrors, fmt.Errorf("failed to commit bundle: %w", err))
				orderFailed = true
			} else {
				usedBundles = append(usedBundles, *bundle)
			}
		} else if sbundle := order.SBundle(); sbundle != nil {
			usedEntry := types.UsedSBundle{
				Bundle: sbundle.Bundle,
			}
			err = changes.CommitSBundle(sbundle, chData, key, algoConf)
			if err != nil {
				buildBlockErrors = append(buildBlockErrors, fmt.Errorf("failed to commit sbundle: %w", err))
				orderFailed = true
				usedEntry.Success = false
			} else {
				usedEntry.Success = true
			}
			usedSbundles = append(usedSbundles, usedEntry)
		} else {
			// note: this should never happen because we should not be inserting invalid transaction types into
			// the orders heap
			panic("unsupported order type found")
		}

		if orderFailed {
			if err = changes.revert(); err != nil {
				log.Error("Failed to revert changes with multi-transaction snapshot", "err", err)
				buildBlockErrors = append(buildBlockErrors, fmt.Errorf("failed to revert changes: %w", err))
			}
		} else {
			if err = changes.apply(); err != nil {
				log.Error("Failed to apply changes with multi-transaction snapshot", "err", err)
				buildBlockErrors = append(buildBlockErrors, fmt.Errorf("failed to apply changes: %w", err))
			}
		}
	}

	return usedBundles, usedSbundles, errors.Join(buildBlockErrors...)
}
