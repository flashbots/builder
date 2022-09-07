package builder

import (
	"errors"
	"math/big"
	_ "os"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/beacon"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"

	"github.com/flashbots/go-boost-utils/bls"
	boostTypes "github.com/flashbots/go-boost-utils/types"
)

type PubkeyHex string

type ValidatorData struct {
	Pubkey       PubkeyHex
	FeeRecipient boostTypes.Address `json:"feeRecipient"`
	GasLimit     uint64             `json:"gasLimit"`
	Timestamp    uint64             `json:"timestamp"`
}

type IBeaconClient interface {
	isValidator(pubkey PubkeyHex) bool
	getProposerForNextSlot(requestedSlot uint64) (PubkeyHex, error)
	onForkchoiceUpdate() (uint64, error)
}

type IRelay interface {
	SubmitBlock(msg *boostTypes.BuilderSubmitBlockRequest) error
	GetValidatorForSlot(nextSlot uint64) (ValidatorData, error)
}

type IBuilder interface {
	OnPayloadAttribute(attrs *BuilderPayloadAttributes) error
	Start() error
	Stop() error
}

type Builder struct {
	ds                         IDatabaseService
	beaconClient               IBeaconClient
	relay                      IRelay
	eth                        IEthereumService
	resubmitter                Resubmitter
	blockSubmissionRateLimiter *BlockSubmissionRateLimiter

	builderSecretKey     *bls.SecretKey
	builderPublicKey     boostTypes.PublicKey
	builderSigningDomain boostTypes.Domain

	bestMu          sync.Mutex
	bestAttrs       BuilderPayloadAttributes
	bestBlockProfit *big.Int
}

func NewBuilder(sk *bls.SecretKey, ds IDatabaseService, bc IBeaconClient, relay IRelay, builderSigningDomain boostTypes.Domain, eth IEthereumService) *Builder {
	pkBytes := bls.PublicKeyFromSecretKey(sk).Compress()
	pk := boostTypes.PublicKey{}
	pk.FromSlice(pkBytes)

	return &Builder{
		ds:                         ds,
		beaconClient:               bc,
		relay:                      relay,
		eth:                        eth,
		resubmitter:                Resubmitter{},
		blockSubmissionRateLimiter: NewBlockSubmissionRateLimiter(),
		builderSecretKey:           sk,
		builderPublicKey:           pk,

		builderSigningDomain: builderSigningDomain,
		bestBlockProfit:      big.NewInt(0),
	}
}

func (b *Builder) Start() error {
	b.blockSubmissionRateLimiter.Start()
	return nil
}

func (b *Builder) Stop() error {
	b.blockSubmissionRateLimiter.Stop()
	return nil
}

func (b *Builder) onSealedBlock(block *types.Block, bundles []types.SimulatedBundle, proposerPubkey boostTypes.PublicKey, proposerFeeRecipient boostTypes.Address, attrs *BuilderPayloadAttributes) error {
	b.bestMu.Lock()
	defer b.bestMu.Unlock()

	// Do not submit blocks that don't improve the profit
	if b.bestAttrs != *attrs {
		b.bestAttrs = *attrs
		b.bestBlockProfit.SetInt64(0)
	} else {
		if block.Profit.Cmp(b.bestBlockProfit) <= 0 {
			log.Info("Ignoring block that is not improving the profit")
			return nil
		}
	}

	executableData := beacon.BlockToExecutableData(block)
	payload, err := executableDataToExecutionPayload(executableData)
	if err != nil {
		log.Error("could not format execution payload", "err", err)
		return err
	}

	value := new(boostTypes.U256Str)
	err = value.FromBig(block.Profit)
	if err != nil {
		log.Error("could not set block value", "err", err)
		return err
	}

	blockBidMsg := boostTypes.BidTrace{
		Slot:                 attrs.Slot,
		ParentHash:           payload.ParentHash,
		BlockHash:            payload.BlockHash,
		BuilderPubkey:        b.builderPublicKey,
		ProposerPubkey:       proposerPubkey,
		ProposerFeeRecipient: proposerFeeRecipient,
		GasLimit:             executableData.GasLimit,
		GasUsed:              executableData.GasUsed,
		Value:                *value,
	}

	go b.ds.ConsumeBuiltBlock(block, bundles, &blockBidMsg)

	signature, err := boostTypes.SignMessage(&blockBidMsg, b.builderSigningDomain, b.builderSecretKey)
	if err != nil {
		log.Error("could not sign builder bid", "err", err)
		return err
	}

	blockSubmitReq := boostTypes.BuilderSubmitBlockRequest{
		Signature:        signature,
		Message:          &blockBidMsg,
		ExecutionPayload: payload,
	}

	err = b.relay.SubmitBlock(&blockSubmitReq)
	if err != nil {
		log.Error("could not submit block", "err", err)
		return err
	}

	log.Info("submitted block", "header", block.Header(), "bid", blockBidMsg)

	b.bestBlockProfit.Set(block.Profit)
	return nil
}

func (b *Builder) OnPayloadAttribute(attrs *BuilderPayloadAttributes) error {
	if attrs == nil {
		return nil
	}

	vd, err := b.relay.GetValidatorForSlot(attrs.Slot)
	if err != nil {
		log.Info("could not get validator while submitting block", "err", err, "slot", attrs.Slot)
		return err
	}

	attrs.SuggestedFeeRecipient = [20]byte(vd.FeeRecipient)
	attrs.GasLimit = vd.GasLimit

	proposerPubkey, err := boostTypes.HexToPubkey(string(vd.Pubkey))
	if err != nil {
		log.Error("could not parse pubkey", "err", err, "pubkey", vd.Pubkey)
		return err
	}

	if !b.eth.Synced() {
		return errors.New("backend not Synced")
	}

	parentBlock := b.eth.GetBlockByHash(attrs.HeadHash)
	if parentBlock == nil {
		log.Info("Block hash not found in blocktree", "head block hash", attrs.HeadHash)
		return errors.New("parent block not found in blocktree")
	}

	blockHook := func(block *types.Block, bundles []types.SimulatedBundle) {
		select {
		case shouldSubmit := <-b.blockSubmissionRateLimiter.Limit(block):
			if !shouldSubmit {
				log.Info("Block rate limited", "blochHash", block.Hash())
				return
			}
		case <-time.After(200 * time.Millisecond):
			log.Info("Block rate limit timeout, submitting the block anyway")
		}

		err := b.onSealedBlock(block, bundles, proposerPubkey, vd.FeeRecipient, attrs)
		if err != nil {
			log.Error("could not run sealed block hook", "err", err)
		}
	}

	firstBlockResult := b.resubmitter.newTask(12*time.Second, time.Second, func() error {
		log.Info("Resubmitting build job")
		return b.eth.BuildBlock(attrs, blockHook)
	})

	return firstBlockResult
}

func executableDataToExecutionPayload(data *beacon.ExecutableDataV1) (*boostTypes.ExecutionPayload, error) {
	transactionData := make([]hexutil.Bytes, len(data.Transactions))
	for i, tx := range data.Transactions {
		transactionData[i] = hexutil.Bytes(tx)
	}

	baseFeePerGas := new(boostTypes.U256Str)
	err := baseFeePerGas.FromBig(data.BaseFeePerGas)
	if err != nil {
		return nil, err
	}

	return &boostTypes.ExecutionPayload{
		ParentHash:    [32]byte(data.ParentHash),
		FeeRecipient:  [20]byte(data.FeeRecipient),
		StateRoot:     [32]byte(data.StateRoot),
		ReceiptsRoot:  [32]byte(data.ReceiptsRoot),
		LogsBloom:     boostTypes.Bloom(types.BytesToBloom(data.LogsBloom)),
		Random:        [32]byte(data.Random),
		BlockNumber:   data.Number,
		GasLimit:      data.GasLimit,
		GasUsed:       data.GasUsed,
		Timestamp:     data.Timestamp,
		ExtraData:     data.ExtraData,
		BaseFeePerGas: *baseFeePerGas,
		BlockHash:     [32]byte(data.BlockHash),
		Transactions:  transactionData,
	}, nil
}
