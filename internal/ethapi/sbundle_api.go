package ethapi

import (
	"context"
	"errors"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/rpc"
)

const maxDepth = 1
const maxBodySize = 50
const simTimeout = time.Second * 5

var (
	ErrMaxDepth         = errors.New("max depth reached")
	ErrUnmatchedBundle  = errors.New("unmatched bundle")
	ErrBundleTooLarge   = errors.New("bundle too large")
	ErrInvalidValidity  = errors.New("invalid validity")
	ErrInvalidInclusion = errors.New("invalid inclusion")
)

type MevAPI struct {
	b     Backend
	chain *core.BlockChain
}

func NewMevAPI(b Backend, chain *core.BlockChain) *MevAPI {
	return &MevAPI{b, chain}
}

type SendMevBundleArgs struct {
	Version   string               `json:"version"`
	Inclusion MevBundleInclusion   `json:"inclusion"`
	Body      []MevBundleBody      `json:"body"`
	Validity  types.BundleValidity `json:"validity"`
}

type MevBundleInclusion struct {
	BlockNumber hexutil.Uint64 `json:"block"`
	MaxBlock    hexutil.Uint64 `json:"maxBlock"`
}

type MevBundleBody struct {
	Hash      *common.Hash       `json:"hash,omitempty"`
	Tx        *hexutil.Bytes     `json:"tx,omitempty"`
	Bundle    *SendMevBundleArgs `json:"bundle,omitempty"`
	CanRevert bool               `json:"canRevert,omitempty"`
}

func ParseSBundleArgs(args *SendMevBundleArgs) (bundle types.SBundle, err error) {
	return parseBundleInner(0, args)
}

func ConvertSBundleToArgs(bundle *types.SBundle) (args SendMevBundleArgs, err error) {
	args.Version = "v0.1"
	args.Inclusion.BlockNumber = hexutil.Uint64(bundle.Inclusion.BlockNumber)
	if bundle.Inclusion.MaxBlockNumber != bundle.Inclusion.BlockNumber {
		args.Inclusion.MaxBlock = hexutil.Uint64(bundle.Inclusion.MaxBlockNumber)
	}
	for _, el := range bundle.Body {
		if el.Tx != nil {
			txBytes, err := el.Tx.MarshalBinary()
			if err != nil {
				return args, err
			}
			args.Body = append(args.Body, MevBundleBody{
				Tx:        (*hexutil.Bytes)(&txBytes),
				CanRevert: el.CanRevert,
			})
		}
		if el.Bundle != nil {
			innerArgs, err := ConvertSBundleToArgs(el.Bundle)
			if err != nil {
				return args, err
			}
			args.Body = append(args.Body, MevBundleBody{
				Bundle: &innerArgs,
			})
		}
	}
	args.Validity.Refund = bundle.Validity.Refund
	args.Validity.RefundConfig = bundle.Validity.RefundConfig
	return args, nil
}

func parseBundleInner(level int, args *SendMevBundleArgs) (bundle types.SBundle, err error) {
	if level > maxDepth {
		return bundle, ErrMaxDepth
	}

	bundle.Inclusion.BlockNumber = uint64(args.Inclusion.BlockNumber)
	if args.Inclusion.MaxBlock > 0 {
		bundle.Inclusion.MaxBlockNumber = uint64(args.Inclusion.MaxBlock)
	} else {
		bundle.Inclusion.MaxBlockNumber = uint64(args.Inclusion.BlockNumber)
	}
	if bundle.Inclusion.MaxBlockNumber < bundle.Inclusion.BlockNumber {
		return bundle, ErrInvalidInclusion
	}
	if bundle.Inclusion.BlockNumber == 0 {
		return bundle, ErrInvalidInclusion
	}

	if len(bundle.Body) > maxBodySize {
		return bundle, ErrBundleTooLarge
	}

	bundle.Body = make([]types.BundleBody, len(args.Body))
	for i, el := range args.Body {
		if el.Hash != nil {
			return bundle, ErrUnmatchedBundle
		} else if el.Tx != nil {
			var tx types.Transaction
			if err := tx.UnmarshalBinary(*el.Tx); err != nil {
				return bundle, err
			}
			bundle.Body[i].Tx = &tx
			if el.CanRevert {
				bundle.Body[i].CanRevert = true
			}
		} else if el.Bundle != nil {
			innerBundle, err := parseBundleInner(level+1, el.Bundle)
			if err != nil {
				return bundle, err
			}
			bundle.Body[i].Bundle = &innerBundle
		}
	}

	maxIdx := len(bundle.Body) - 1
	totalPercent := 0
	for _, el := range args.Validity.Refund {
		if el.BodyIdx < 0 || el.BodyIdx > maxIdx {
			return bundle, ErrInvalidValidity
		}
		if el.Percent < 0 || el.Percent > 100 {
			return bundle, ErrInvalidValidity
		}
		totalPercent += el.Percent
	}
	if totalPercent > 100 {
		return bundle, ErrInvalidValidity
	}
	totalPercent = 0
	for _, el := range args.Validity.RefundConfig {
		percent := el.Percent
		if percent < 0 || percent > 100 {
			return bundle, ErrInvalidValidity
		}
		totalPercent += percent
	}
	if totalPercent > 100 {
		return bundle, ErrInvalidValidity
	}
	bundle.Validity = args.Validity

	return bundle, nil
}

func (api *MevAPI) SendBundle(ctx context.Context, args SendMevBundleArgs) error {
	bundle, err := parseBundleInner(0, &args)
	if err != nil {
		return err
	}
	go api.b.SendSBundle(ctx, &bundle)
	return nil
}

type SimMevBundleResponse struct {
	Success           bool                     `json:"success"`
	Error             string                   `json:"error,omitempty"`
	StateBlock        hexutil.Uint64           `json:"stateBlock"`
	EffectiveGasPrice hexutil.Big              `json:"effectiveGasPrice"`
	Profit            hexutil.Big              `json:"profit"`
	RefundableValue   hexutil.Big              `json:"refundableValue"`
	GasUsed           hexutil.Uint64           `json:"gasUsed"`
	BodyLogs          []core.SimBundleBodyLogs `json:"logs,omitempty"`
}

func (api *MevAPI) SimBundle(ctx context.Context, args SendMevBundleArgs) (*SimMevBundleResponse, error) {
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(ctx, simTimeout)
	defer cancel()

	bundle, err := ParseSBundleArgs(&args)
	if err != nil {
		return nil, err
	}

	currHeader := api.b.CurrentHeader()
	if currHeader == nil {
		return nil, errors.New("no current header")
	}

	stateBlock := currHeader.Number.Uint64()

	nextBlock := stateBlock + 1
	minBlock := bundle.Inclusion.BlockNumber
	maxBlock := bundle.Inclusion.MaxBlockNumber
	if minBlock > nextBlock {
		return nil, errors.New("min stateBlock is in the future")
	}
	if maxBlock < nextBlock {
		// select past stateBlock
		stateBlock = maxBlock - 1
		nextBlock = maxBlock
	}

	state, parent, err := api.b.StateAndHeaderByNumber(ctx, rpc.BlockNumber(stateBlock))
	if err != nil {
		return nil, err
	}
	header := types.Header{
		ParentHash: parent.Hash(),
		Number:     new(big.Int).SetUint64(nextBlock),
		GasLimit:   parent.GasLimit,
		Time:       parent.Time + 12,
		Difficulty: new(big.Int).Set(parent.Difficulty),
		Coinbase:   parent.Coinbase,
		BaseFee:    misc.CalcBaseFee(api.b.ChainConfig(), parent),
	}

	gp := new(core.GasPool).AddGas(header.GasLimit)

	result := &SimMevBundleResponse{}
	tmpGasUsed := uint64(0)
	bundleRes, err := core.SimBundle(api.b.ChainConfig(), api.chain, &header.Coinbase, gp, state, &header, &bundle, 0, &tmpGasUsed, vm.Config{}, true)
	if err != nil {
		result.Success = false
		result.Error = err.Error()
	} else {
		result.Success = true
		result.BodyLogs = bundleRes.BodyLogs
	}
	result.StateBlock = hexutil.Uint64(stateBlock)
	result.EffectiveGasPrice = hexutil.Big(*bundleRes.MevGasPrice)
	result.Profit = hexutil.Big(*bundleRes.TotalProfit)
	result.RefundableValue = hexutil.Big(*bundleRes.RefundableValue)
	result.GasUsed = hexutil.Uint64(bundleRes.GasUsed)

	return result, nil
}

func (api *MevAPI) CancelBundleByHash(ctx context.Context, hash common.Hash) error {
	go api.b.CancelSBundles(ctx, []common.Hash{hash})
	return nil
}
