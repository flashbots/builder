package blockvalidation

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"

	bellatrixapi "github.com/attestantio/go-builder-client/api/bellatrix"
	capellaapi "github.com/attestantio/go-builder-client/api/capella"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	bellatrixUtil "github.com/attestantio/go-eth2-client/util/bellatrix"
	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/eth/tracers/logger"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/miner"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/rpc"
	boostTypes "github.com/flashbots/go-boost-utils/types"
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
	// If set to true, proposer payment is assumed to be in the last transaction of the block.
	ForceLastTxPayment bool
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
			Service:   NewBlockValidationAPI(backend, accessVerifier, cfg.ForceLastTxPayment),
		},
	})
	return nil
}

type BlockValidationAPI struct {
	eth            *eth.Ethereum
	accessVerifier *AccessVerifier
	// If set to true, proposer payment is assumed to be in the last transaction of the block.
	forceLastTxPayment bool
}

// NewConsensusAPI creates a new consensus api for the given backend.
// The underlying blockchain needs to have a valid terminal total difficulty set.
func NewBlockValidationAPI(eth *eth.Ethereum, accessVerifier *AccessVerifier, forceLastTxPayment bool) *BlockValidationAPI {
	return &BlockValidationAPI{
		eth:                eth,
		accessVerifier:     accessVerifier,
		forceLastTxPayment: forceLastTxPayment,
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

	err = api.eth.BlockChain().ValidatePayload(block, feeRecipient, expectedProfit, params.RegisteredGasLimit, vmconfig, api.forceLastTxPayment)
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

type BlockAssemblerRequest struct {
	TobTxs             bellatrixUtil.ExecutionPayloadTransactions
	RobPayload         capellaapi.SubmitBlockRequest
	RegisteredGasLimit uint64
}

type IntermediateBlockAssemblerRequest struct {
	TobTxs             []byte                        `json:"tob_txs"`
	RobPayload         capellaapi.SubmitBlockRequest `json:"rob_payload"`
	RegisteredGasLimit uint64                        `json:"registered_gas_limit,string"`
}

func (b *BlockAssemblerRequest) UnmarshalJSON(data []byte) error {
	var intermediateJson IntermediateBlockAssemblerRequest
	err := json.Unmarshal(data, &intermediateJson)
	if err != nil {
		return err
	}
	err = b.TobTxs.UnmarshalSSZ(intermediateJson.TobTxs)
	if err != nil {
		return err
	}
	b.RegisteredGasLimit = intermediateJson.RegisteredGasLimit
	b.RobPayload = intermediateJson.RobPayload

	return nil
}

// bchain: copied this here to avoid circular dependency
func executableDataToCapellaExecutionPayload(data *engine.ExecutableData) (*capella.ExecutionPayload, error) {
	transactionData := make([]bellatrix.Transaction, len(data.Transactions))
	for i, tx := range data.Transactions {
		transactionData[i] = tx
	}

	withdrawalData := make([]*capella.Withdrawal, len(data.Withdrawals))
	for i, wd := range data.Withdrawals {
		withdrawalData[i] = &capella.Withdrawal{
			Index:          capella.WithdrawalIndex(wd.Index),
			ValidatorIndex: phase0.ValidatorIndex(wd.Validator),
			Address:        bellatrix.ExecutionAddress(wd.Address),
			Amount:         phase0.Gwei(wd.Amount),
		}
	}

	baseFeePerGas := new(boostTypes.U256Str)
	err := baseFeePerGas.FromBig(data.BaseFeePerGas)
	if err != nil {
		return nil, err
	}

	return &capella.ExecutionPayload{
		ParentHash:    [32]byte(data.ParentHash),
		FeeRecipient:  [20]byte(data.FeeRecipient),
		StateRoot:     data.StateRoot,
		ReceiptsRoot:  data.ReceiptsRoot,
		LogsBloom:     types.BytesToBloom(data.LogsBloom),
		PrevRandao:    data.Random,
		BlockNumber:   data.Number,
		GasLimit:      data.GasLimit,
		GasUsed:       data.GasUsed,
		Timestamp:     data.Timestamp,
		ExtraData:     data.ExtraData,
		BaseFeePerGas: *baseFeePerGas,
		BlockHash:     [32]byte(data.BlockHash),
		Transactions:  transactionData,
		Withdrawals:   withdrawalData,
	}, nil
}

func (api *BlockValidationAPI) BlockAssembler(params *BlockAssemblerRequest) (*capella.ExecutionPayload, error) {
	log.Info("BlockAssembler", "tobTxs", len(params.TobTxs.Transactions), "robPayload", params.RobPayload)
	transactionBytes := make([][]byte, len(params.TobTxs.Transactions))
	for i, txHexBytes := range params.TobTxs.Transactions {
		transactionBytes[i] = txHexBytes[:]
	}
	txs, err := engine.DecodeTransactions(transactionBytes)
	if err != nil {
		return nil, err
	}

	robBlock, err := engine.ExecutionPayloadV2ToBlock(params.RobPayload.ExecutionPayload)
	if err != nil {
		return nil, err
	}

	// TODO - check for gas limits
	// TODO - support for payouts

	// check if there are any duplicate txs
	// we can error out if there is a nonce gap
	// TODO - don't error out, but drop the duplicate tx in the ROB block
	seenTxMap := make(map[common.Hash]struct{})
	for _, tx := range txs {
		// If we see nonce reuse in TOB then fail
		if _, ok := seenTxMap[tx.Hash()]; ok {
			return nil, errors.New("duplicate tx")
		}
		seenTxMap[tx.Hash()] = struct{}{}
	}
	for _, tx := range robBlock.Transactions() {
		// if we see nonce re-use in TOB vs ROB then drop txs the txs in ROB
		if _, ok := seenTxMap[tx.Hash()]; ok {
			return nil, errors.New("duplicate tx")
		}
		seenTxMap[tx.Hash()] = struct{}{}
	}

	withdrawals := make(types.Withdrawals, len(params.RobPayload.ExecutionPayload.Withdrawals))
	for _, withdrawal := range params.RobPayload.ExecutionPayload.Withdrawals {
		withdrawals = append(withdrawals, &types.Withdrawal{
			Index:     uint64(withdrawal.Index),
			Validator: uint64(withdrawal.ValidatorIndex),
			Address:   common.Address(withdrawal.Address),
			Amount:    uint64(withdrawal.Amount),
		})
	}

	// assemble the txs in map[sender]txs format and pass it in the BuildPayload call
	robTxs := robBlock.Transactions()
	block, err := api.eth.Miner().PayloadAssembler(&miner.BuildPayloadArgs{
		Parent:    common.Hash(params.RobPayload.ExecutionPayload.ParentHash),
		Timestamp: params.RobPayload.ExecutionPayload.Timestamp,
		// TODO - this should be relayer fee recipient. We will implement payouts later
		FeeRecipient: common.Address(params.RobPayload.Message.ProposerFeeRecipient),
		GasLimit:     params.RegisteredGasLimit,
		Random:       params.RobPayload.ExecutionPayload.PrevRandao,
		Withdrawals:  withdrawals,
		BlockHook:    nil,
		AssemblerTxs: miner.AssemblerTxLists{
			TobTxs: txs,
			RobTxs: &robTxs,
		},
	})
	if err != nil {
		return nil, err
	}
	resolvedBlock := block.ResolveFull()
	if resolvedBlock == nil {
		return nil, errors.New("unable to resolve block")
	}
	if resolvedBlock.ExecutionPayload == nil {
		return nil, errors.New("nil execution payload")
	}

	finalPayload, err := executableDataToCapellaExecutionPayload(resolvedBlock.ExecutionPayload)

	return finalPayload, nil
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

	err = api.eth.BlockChain().ValidatePayload(block, feeRecipient, expectedProfit, params.RegisteredGasLimit, vmconfig, api.forceLastTxPayment)
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
