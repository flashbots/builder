package builder

import (
	"context"
	"errors"
	"math/big"
	_ "os"
	"sync"
	"time"

	blockvalidation "github.com/ethereum/go-ethereum/eth/block-validation"
	"golang.org/x/time/rate"

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
	FeeRecipient boostTypes.Address
	GasLimit     uint64
}

type IBeaconClient interface {
	isValidator(pubkey PubkeyHex) bool
	getProposerForNextSlot(requestedSlot uint64) (PubkeyHex, error)
	onForkchoiceUpdate() (uint64, error)
	updateValidatorsMap() error
}

type IRelay interface {
	SubmitBlock(msg *boostTypes.BuilderSubmitBlockRequest, vd ValidatorData) error
	GetValidatorForSlot(nextSlot uint64) (ValidatorData, error)
	Start() error
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
	dryRun               bool
	validator            *blockvalidation.BlockValidationAPI
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

func NewBuilder(sk *bls.SecretKey, ds flashbotsextra.IDatabaseService, relay IRelay, builderSigningDomain boostTypes.Domain, eth IEthereumService, dryRun bool, validator *blockvalidation.BlockValidationAPI) *Builder {
	pkBytes := bls.PublicKeyFromSecretKey(sk).Compress()
	pk := boostTypes.PublicKey{}
	pk.FromSlice(pkBytes)

	slotCtx, slotCtxCancel := context.WithCancel(context.Background())
	return &Builder{
		ds:                   ds,
		relay:                relay,
		eth:                  eth,
		dryRun:               dryRun,
		validator:            validator,
		builderSecretKey:     sk,
		builderPublicKey:     pk,
		builderSigningDomain: builderSigningDomain,

		limiter:       rate.NewLimiter(rate.Every(time.Millisecond), 510),
		slot:          0,
		slotCtx:       slotCtx,
		slotCtxCancel: slotCtxCancel,
	}
}

func (b *Builder) Start() error {
	return b.relay.Start()	
}

func (b *Builder) Stop() error {
	return nil
}

func (b *Builder) onSealedBlock(block *types.Block, ordersClosedAt time.Time, sealedAt time.Time, commitedBundles []types.SimulatedBundle, allBundles []types.SimulatedBundle, proposerPubkey boostTypes.PublicKey, vd ValidatorData, attrs *BuilderPayloadAttributes) error {
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
		ProposerFeeRecipient: vd.FeeRecipient,
		GasLimit:             executableData.GasLimit,
		GasUsed:              executableData.GasUsed,
		Value:                *value,
	}

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

	if b.dryRun {
		err = b.validator.ValidateBuilderSubmissionV1(&blockvalidation.BuilderBlockValidationRequest{BuilderSubmitBlockRequest: blockSubmitReq, RegisteredGasLimit: vd.GasLimit})
		if err != nil {
			log.Error("could not validate block", "err", err)
		}
	} else {
		go b.ds.ConsumeBuiltBlock(block, ordersClosedAt, sealedAt, commitedBundles, allBundles, &blockBidMsg)
		err = b.relay.SubmitBlock(&blockSubmitReq, vd)
		if err != nil {
			log.Error("could not submit block", "err", err, "#commitedBundles", len(commitedBundles))
			return err
		}
	}

	log.Info("submitted block", "slot", blockBidMsg.Slot, "value", blockBidMsg.Value.String(), "parent", blockBidMsg.ParentHash, "hash", block.Hash(), "#commitedBundles", len(commitedBundles))

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

	go b.runBuildingJob(b.slotCtx, proposerPubkey, vd, attrs)
	return nil
}

type blockQueueEntry struct {
	block           *types.Block
	ordersCloseTime time.Time
	sealedAt        time.Time
	commitedBundles []types.SimulatedBundle
	allBundles      []types.SimulatedBundle
}

func (b *Builder) runBuildingJob(slotCtx context.Context, proposerPubkey boostTypes.PublicKey, vd ValidatorData, attrs *BuilderPayloadAttributes) {
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
		queueBestEntry           blockQueueEntry
	)

	log.Debug("runBuildingJob", "slot", attrs.Slot, "parent", attrs.HeadHash)

	submitBestBlock := func() {
		queueMu.Lock()
		if queueLastSubmittedProfit.Cmp(queueBestProfit) < 0 {
			err := b.onSealedBlock(queueBestEntry.block, queueBestEntry.ordersCloseTime, queueBestEntry.sealedAt, queueBestEntry.commitedBundles, queueBestEntry.allBundles, proposerPubkey, vd, attrs)

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
	blockHook := func(block *types.Block, ordersCloseTime time.Time, commitedBundles []types.SimulatedBundle, allBundles []types.SimulatedBundle) {
		if ctx.Err() != nil {
			return
		}

		sealedAt := time.Now()

		queueMu.Lock()
		defer queueMu.Unlock()
		if block.Profit.Cmp(queueBestProfit) > 0 {
			queueBestEntry = blockQueueEntry{
				block:           block,
				ordersCloseTime: ordersCloseTime,
				sealedAt:        sealedAt,
				commitedBundles: commitedBundles,
				allBundles:      allBundles,
			}
			queueBestProfit.Set(block.Profit)

			select {
			case queueSignal <- struct{}{}:
			default:
			}
		}
	}

	// resubmits block builder requests every second
	runRetryLoop(ctx, 500*time.Millisecond, func() {
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
