package blockvalidation

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"

	bellatrixapi "github.com/attestantio/go-builder-client/api/bellatrix"
	capellaapi "github.com/attestantio/go-builder-client/api/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/eth/tracers/logger"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/rpc"
)

type BlacklistedAddresses []common.Address

type AccessVerifier struct {
	blacklistedAddresses map[common.Address]struct{}
}

func (a *AccessVerifier) verifyTraces(tracer *logger.AccessListTracer) error {
	log.Trace("x", "tracer.AccessList()", tracer.AccessList())
	for _, accessTuple := range tracer.AccessList() {
		// TODO: should we ignore common.Address{}?
		if _, found := a.blacklistedAddresses[accessTuple.Address]; found {
			log.Info("bundle accesses blacklisted address", "address", accessTuple.Address)
			return fmt.Errorf("blacklisted address %s in execution trace", accessTuple.Address.String())
		}
	}

	return nil
}

func (a *AccessVerifier) isBlacklisted(addr common.Address) error {
	if _, present := a.blacklistedAddresses[addr]; present {
		return fmt.Errorf("transaction from blacklisted address %s", addr.String())
	}
	return nil
}

func (a *AccessVerifier) verifyTransactions(signer types.Signer, txs types.Transactions) error {
	for _, tx := range txs {
		from, err := types.Sender(signer, tx)
		if err == nil {
			if _, present := a.blacklistedAddresses[from]; present {
				return fmt.Errorf("transaction from blacklisted address %s", from.String())
			}
		}
		to := tx.To()
		if to != nil {
			if _, present := a.blacklistedAddresses[*to]; present {
				return fmt.Errorf("transaction to blacklisted address %s", to.String())
			}
		}
	}
	return nil
}

func NewAccessVerifierFromFile(path string) (*AccessVerifier, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var ba BlacklistedAddresses
	if err := json.Unmarshal(bytes, &ba); err != nil {
		return nil, err
	}

	blacklistedAddresses := make(map[common.Address]struct{}, len(ba))
	for _, address := range ba {
		blacklistedAddresses[address] = struct{}{}
	}

	return &AccessVerifier{
		blacklistedAddresses: blacklistedAddresses,
	}, nil
}

type BlockValidationConfig struct {
	BlacklistSourceFilePath string
	// If set to true, proposer payment is calculated as a balance difference of the fee recipient.
	UseBalanceDiffProfit bool
}

// Register adds catalyst APIs to the full node.
func Register(stack *node.Node, backend *eth.Ethereum, cfg BlockValidationConfig) error {
	var accessVerifier *AccessVerifier
	if cfg.BlacklistSourceFilePath != "" {
		var err error
		accessVerifier, err = NewAccessVerifierFromFile(cfg.BlacklistSourceFilePath)
		if err != nil {
			return err
		}
	}

	stack.RegisterAPIs([]rpc.API{
		{
			Namespace: "flashbots",
			Service:   NewBlockValidationAPI(backend, accessVerifier, cfg.UseBalanceDiffProfit),
		},
	})
	return nil
}

type BlockValidationAPI struct {
	eth            *eth.Ethereum
	accessVerifier *AccessVerifier
	// If set to true, proposer payment is calculated as a balance difference of the fee recipient.
	useBalanceDiffProfit bool
}

// NewConsensusAPI creates a new consensus api for the given backend.
// The underlying blockchain needs to have a valid terminal total difficulty set.
func NewBlockValidationAPI(eth *eth.Ethereum, accessVerifier *AccessVerifier, useBalanceDiffProfit bool) *BlockValidationAPI {
	return &BlockValidationAPI{
		eth:                  eth,
		accessVerifier:       accessVerifier,
		useBalanceDiffProfit: useBalanceDiffProfit,
	}
}

type BuilderBlockValidationRequest struct {
	bellatrixapi.SubmitBlockRequest
	RegisteredGasLimit uint64 `json:"registered_gas_limit,string"`
}

func (api *BlockValidationAPI) ValidateBuilderSubmissionV1(params *BuilderBlockValidationRequest) error {
	// TODO: fuzztest, make sure the validation is sound
	// TODO: handle context!

	if params.ExecutionPayload == nil {
		return errors.New("nil execution payload")
	}
	payload := params.ExecutionPayload
	block, err := engine.ExecutionPayloadToBlock(payload)
	if err != nil {
		return err
	}

	if params.Message.ParentHash != phase0.Hash32(block.ParentHash()) {
		return fmt.Errorf("incorrect ParentHash %s, expected %s", params.Message.ParentHash.String(), block.ParentHash().String())
	}

	if params.Message.BlockHash != phase0.Hash32(block.Hash()) {
		return fmt.Errorf("incorrect BlockHash %s, expected %s", params.Message.BlockHash.String(), block.Hash().String())
	}

	if params.Message.GasLimit != block.GasLimit() {
		return fmt.Errorf("incorrect GasLimit %d, expected %d", params.Message.GasLimit, block.GasLimit())
	}

	if params.Message.GasUsed != block.GasUsed() {
		return fmt.Errorf("incorrect GasUsed %d, expected %d", params.Message.GasUsed, block.GasUsed())
	}

	feeRecipient := common.BytesToAddress(params.Message.ProposerFeeRecipient[:])
	expectedProfit := params.Message.Value.ToBig()

	var vmconfig vm.Config
	var tracer *logger.AccessListTracer = nil
	if api.accessVerifier != nil {
		if err := api.accessVerifier.isBlacklisted(block.Coinbase()); err != nil {
			return err
		}
		if err := api.accessVerifier.isBlacklisted(feeRecipient); err != nil {
			return err
		}
		if err := api.accessVerifier.verifyTransactions(types.LatestSigner(api.eth.BlockChain().Config()), block.Transactions()); err != nil {
			return err
		}
		isPostMerge := true // the call is PoS-native
		timestamp := params.SubmitBlockRequest.ExecutionPayload.Timestamp
		precompiles := vm.ActivePrecompiles(api.eth.APIBackend.ChainConfig().Rules(new(big.Int).SetUint64(params.ExecutionPayload.BlockNumber), isPostMerge, timestamp))
		tracer = logger.NewAccessListTracer(nil, common.Address{}, common.Address{}, precompiles)
		vmconfig = vm.Config{Tracer: tracer, Debug: true}
	}

	err = api.eth.BlockChain().ValidatePayload(block, feeRecipient, expectedProfit, params.RegisteredGasLimit, vmconfig, api.useBalanceDiffProfit)
	if err != nil {
		log.Error("invalid payload", "hash", payload.BlockHash.String(), "number", payload.BlockNumber, "parentHash", payload.ParentHash.String(), "err", err)
		return err
	}

	if api.accessVerifier != nil && tracer != nil {
		if err := api.accessVerifier.verifyTraces(tracer); err != nil {
			return err
		}
	}

	log.Info("validated block", "hash", block.Hash(), "number", block.NumberU64(), "parentHash", block.ParentHash())
	return nil
}

type BuilderBlockValidationRequestV2 struct {
	capellaapi.SubmitBlockRequest
	RegisteredGasLimit uint64      `json:"registered_gas_limit,string"`
	WithdrawalsRoot    common.Hash `json:"withdrawals_root"`
}

func (r *BuilderBlockValidationRequestV2) UnmarshalJSON(data []byte) error {
	params := &struct {
		RegisteredGasLimit uint64      `json:"registered_gas_limit,string"`
		WithdrawalsRoot    common.Hash `json:"withdrawals_root"`
	}{}
	err := json.Unmarshal(data, params)
	if err != nil {
		return err
	}
	r.RegisteredGasLimit = params.RegisteredGasLimit
	r.WithdrawalsRoot = params.WithdrawalsRoot

	blockRequest := new(capellaapi.SubmitBlockRequest)
	err = json.Unmarshal(data, &blockRequest)
	if err != nil {
		return err
	}
	r.SubmitBlockRequest = *blockRequest
	return nil
}

func (api *BlockValidationAPI) ValidateBuilderSubmissionV2(params *BuilderBlockValidationRequestV2) error {
	// TODO: fuzztest, make sure the validation is sound
	// TODO: handle context!
	if params.ExecutionPayload == nil {
		return errors.New("nil execution payload")
	}
	payload := params.ExecutionPayload
	block, err := engine.ExecutionPayloadV2ToBlock(payload)
	if err != nil {
		return err
	}

	if params.Message.ParentHash != phase0.Hash32(block.ParentHash()) {
		return fmt.Errorf("incorrect ParentHash %s, expected %s", params.Message.ParentHash.String(), block.ParentHash().String())
	}

	if params.Message.BlockHash != phase0.Hash32(block.Hash()) {
		return fmt.Errorf("incorrect BlockHash %s, expected %s", params.Message.BlockHash.String(), block.Hash().String())
	}

	if params.Message.GasLimit != block.GasLimit() {
		return fmt.Errorf("incorrect GasLimit %d, expected %d", params.Message.GasLimit, block.GasLimit())
	}

	if params.Message.GasUsed != block.GasUsed() {
		return fmt.Errorf("incorrect GasUsed %d, expected %d", params.Message.GasUsed, block.GasUsed())
	}

	feeRecipient := common.BytesToAddress(params.Message.ProposerFeeRecipient[:])
	expectedProfit := params.Message.Value.ToBig()

	var vmconfig vm.Config
	var tracer *logger.AccessListTracer = nil
	if api.accessVerifier != nil {
		if err := api.accessVerifier.isBlacklisted(block.Coinbase()); err != nil {
			return err
		}
		if err := api.accessVerifier.isBlacklisted(feeRecipient); err != nil {
			return err
		}
		if err := api.accessVerifier.verifyTransactions(types.LatestSigner(api.eth.BlockChain().Config()), block.Transactions()); err != nil {
			return err
		}
		isPostMerge := true // the call is PoS-native
		precompiles := vm.ActivePrecompiles(api.eth.APIBackend.ChainConfig().Rules(new(big.Int).SetUint64(params.ExecutionPayload.BlockNumber), isPostMerge, params.ExecutionPayload.Timestamp))
		tracer = logger.NewAccessListTracer(nil, common.Address{}, common.Address{}, precompiles)
		vmconfig = vm.Config{Tracer: tracer, Debug: true}
	}

	err = api.eth.BlockChain().ValidatePayload(block, feeRecipient, expectedProfit, params.RegisteredGasLimit, vmconfig, api.useBalanceDiffProfit)
	if err != nil {
		log.Error("invalid payload", "hash", payload.BlockHash.String(), "number", payload.BlockNumber, "parentHash", payload.ParentHash.String(), "err", err)
		return err
	}

	if api.accessVerifier != nil && tracer != nil {
		if err := api.accessVerifier.verifyTraces(tracer); err != nil {
			return err
		}
	}

	log.Info("validated block", "hash", block.Hash(), "number", block.NumberU64(), "parentHash", block.ParentHash())
	return nil
}
