package builder

import (
	"context"
	"errors"
	"golang.org/x/time/rate"
	"math/big"
	_ "os"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/beacon"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/flashbotsextra"
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
	ds                   flashbotsextra.IDatabaseService
	relay                IRelay
	eth                  IEthereumService
	builderSecretKey     *bls.SecretKey
	builderPublicKey     boostTypes.PublicKey
	builderSigningDomain boostTypes.Domain

	limiter *rate.Limiter

	slotMu        sync.Mutex
	slot          uint64
	slotAttrs     []BuilderPayloadAttributes
	slotCtx       context.Context
	slotCtxCancel context.CancelFunc
}

func NewBuilder(sk *bls.SecretKey, ds flashbotsextra.IDatabaseService, relay IRelay, builderSigningDomain boostTypes.Domain, eth IEthereumService) *Builder {
	pkBytes := bls.PublicKeyFromSecretKey(sk).Compress()
	pk := boostTypes.PublicKey{}
	pk.FromSlice(pkBytes)

	slotCtx, slotCtxCancel := context.WithCancel(context.Background())
	return &Builder{
		ds:                   ds,
		relay:                relay,
		eth:                  eth,
		builderSecretKey:     sk,
		builderPublicKey:     pk,
		builderSigningDomain: builderSigningDomain,

		limiter:       rate.NewLimiter(rate.Every(time.Second), 1),
		slot:          0,
		slotCtx:       slotCtx,
		slotCtxCancel: slotCtxCancel,
	}
}

func (b *Builder) Start() error {
	return nil
}

func (b *Builder) Stop() error {
	return nil
}

func (b *Builder) onSealedBlock(block *types.Block, bundles []types.SimulatedBundle, proposerPubkey boostTypes.PublicKey, proposerFeeRecipient boostTypes.Address, attrs *BuilderPayloadAttributes) error {
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
		log.Error("could not submit block", "err", err, "bundles", len(bundles))
		return err
	}

	log.Info("submitted block", "slot", blockBidMsg.Slot, "value", blockBidMsg.Value.String(), "parent", blockBidMsg.ParentHash, "hash", block.Hash(), "bundles", len(bundles))

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
		log.Warn("Block hash not found in blocktree", "head block hash", attrs.HeadHash)
		return errors.New("parent block not found in blocktree")
	}

	b.slotMu.Lock()
	defer b.slotMu.Unlock()

	if b.slot != attrs.Slot {
		if b.slotCtxCancel != nil {
			b.slotCtxCancel()
		}

		slotCtx, slotCtxCancel := context.WithTimeout(context.Background(), 12*time.Second)
		b.slot = attrs.Slot
		b.slotAttrs = nil
		b.slotCtx = slotCtx
		b.slotCtxCancel = slotCtxCancel
	}

	for _, currentAttrs := range b.slotAttrs {
		if *attrs == currentAttrs {
			log.Debug("ignoring known payload attribute", "slot", attrs.Slot, "hash", attrs.HeadHash)
			return nil
		}
	}
	b.slotAttrs = append(b.slotAttrs, *attrs)

	go b.runBuildingJob(b.slotCtx, proposerPubkey, vd.FeeRecipient, attrs)
	return nil
}

func (b *Builder) runBuildingJob(slotCtx context.Context, proposerPubkey boostTypes.PublicKey, feeRecipient boostTypes.Address, attrs *BuilderPayloadAttributes) {
	ctx, cancel := context.WithTimeout(slotCtx, 12*time.Second)
	defer cancel()

	// Submission queue for the given payload attributes
	// multiple jobs can run for different attributes fot the given slot
	// 1. When new block is ready we check if its profit is higher than profit of last best block
	//    if it is we set queueBest* to values of the new block and notify queueSignal channel.
	// 2. Submission goroutine waits for queueSignal and submits queueBest* if its more valuable than
	//    queueLastSubmittedProfit keeping queueLastSubmittedProfit to be the profit of the last submission.
	//    Submission goroutine is globally rate limited to have fixed rate of submissions for all jobs.
	var (
		queueSignal = make(chan struct{}, 1)

		queueMu                  sync.Mutex
		queueLastSubmittedProfit = new(big.Int)
		queueBestProfit          = new(big.Int)
		queueBestBlock           *types.Block
		queueBestBundles         []types.SimulatedBundle
	)

	log.Debug("runBuildingJob", "slot", attrs.Slot, "parent", attrs.HeadHash)

	submitBestBlock := func() {
		queueMu.Lock()
		if queueLastSubmittedProfit.Cmp(queueBestProfit) < 0 {
			err := b.onSealedBlock(queueBestBlock, queueBestBundles, proposerPubkey, feeRecipient, attrs)
			if err != nil {
				log.Error("could not run sealed block hook", "err", err)
			} else {
				queueLastSubmittedProfit.Set(queueBestProfit)
			}
		}
		queueMu.Unlock()
	}

	// Empties queue, submits the best block for current job with rate limit (global for all jobs)
	go runResubmitLoop(ctx, b.limiter, queueSignal, submitBestBlock)

	// Populates queue with submissions that increase block profit
	blockHook := func(block *types.Block, bundles []types.SimulatedBundle) {
		if ctx.Err() != nil {
			return
		}

		queueMu.Lock()
		defer queueMu.Unlock()
		if block.Profit.Cmp(queueBestProfit) > 0 {
			queueBestBlock = block
			queueBestBundles = bundles
			queueBestProfit.Set(block.Profit)

			select {
			case queueSignal <- struct{}{}:
			default:
			}
		}
	}

	// resubmits block builder requests every second
	runRetryLoop(ctx, time.Second, func() {
		log.Debug("retrying BuildBlock", "slot", attrs.Slot, "parent", attrs.HeadHash)
		err := b.eth.BuildBlock(attrs, blockHook)
		if err != nil {
			log.Warn("Failed to build block", "err", err)
		}
	})
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
