package builder

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	_ "os"
	"sync"
	"time"

	bellatrixapi "github.com/attestantio/go-builder-client/api/bellatrix"
	capellaapi "github.com/attestantio/go-builder-client/api/capella"
	apiv1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	blockvalidation "github.com/ethereum/go-ethereum/eth/block-validation"
	"github.com/ethereum/go-ethereum/flashbotsextra"
	"github.com/ethereum/go-ethereum/log"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/ssz"
	boostTypes "github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/go-boost-utils/utils"
	"github.com/holiman/uint256"
	"golang.org/x/time/rate"
)

const (
	RateLimitIntervalDefault     = 500 * time.Millisecond
	RateLimitBurstDefault        = 10
	BlockResubmitIntervalDefault = 500 * time.Millisecond

	SubmissionOffsetFromEndOfSlotSecondsDefault = 3 * time.Second
)

type PubkeyHex string

type ValidatorData struct {
	Pubkey       PubkeyHex
	FeeRecipient bellatrix.ExecutionAddress
	GasLimit     uint64
}

type IRelay interface {
	SubmitBlock(msg *bellatrixapi.SubmitBlockRequest, vd ValidatorData) error
	SubmitBlockCapella(msg *capellaapi.SubmitBlockRequest, vd ValidatorData) error
	GetValidatorForSlot(nextSlot uint64) (ValidatorData, error)
	Config() RelayConfig
	Start() error
	Stop()
}

type IBuilder interface {
	OnPayloadAttribute(attrs *types.BuilderPayloadAttributes) error
	Start() error
	Stop() error
}

type Builder struct {
	ds                          flashbotsextra.IDatabaseService
	relay                       IRelay
	eth                         IEthereumService
	dryRun                      bool
	ignoreLatePayloadAttributes bool
	validator                   *blockvalidation.BlockValidationAPI
	beaconClient                IBeaconClient
	builderSecretKey            *bls.SecretKey
	builderPublicKey            phase0.BLSPubKey
	builderSigningDomain        phase0.Domain
	builderResubmitInterval     time.Duration
	discardRevertibleTxOnErr    bool

	limiter                       *rate.Limiter
	submissionOffsetFromEndOfSlot time.Duration

	slotMu        sync.Mutex
	slotAttrs     types.BuilderPayloadAttributes
	slotCtx       context.Context
	slotCtxCancel context.CancelFunc

	stop chan struct{}
}

// BuilderArgs is a struct that contains all the arguments needed to create a new Builder
type BuilderArgs struct {
	sk                            *bls.SecretKey
	ds                            flashbotsextra.IDatabaseService
	relay                         IRelay
	builderSigningDomain          phase0.Domain
	builderBlockResubmitInterval  time.Duration
	discardRevertibleTxOnErr      bool
	eth                           IEthereumService
	dryRun                        bool
	ignoreLatePayloadAttributes   bool
	validator                     *blockvalidation.BlockValidationAPI
	beaconClient                  IBeaconClient
	submissionOffsetFromEndOfSlot time.Duration

	limiter *rate.Limiter
}

func NewBuilder(args BuilderArgs) (*Builder, error) {
	blsPk, err := bls.PublicKeyFromSecretKey(args.sk)
	if err != nil {
		return nil, err
	}
	pk, err := utils.BlsPublicKeyToPublicKey(blsPk)
	if err != nil {
		return nil, err
	}

	if args.limiter == nil {
		args.limiter = rate.NewLimiter(rate.Every(RateLimitIntervalDefault), RateLimitBurstDefault)
	}

	if args.builderBlockResubmitInterval == 0 {
		args.builderBlockResubmitInterval = BlockResubmitIntervalDefault
	}

	if args.submissionOffsetFromEndOfSlot == 0 {
		args.submissionOffsetFromEndOfSlot = SubmissionOffsetFromEndOfSlotSecondsDefault
	}

	slotCtx, slotCtxCancel := context.WithCancel(context.Background())
	return &Builder{
		ds:                            args.ds,
		relay:                         args.relay,
		eth:                           args.eth,
		dryRun:                        args.dryRun,
		ignoreLatePayloadAttributes:   args.ignoreLatePayloadAttributes,
		validator:                     args.validator,
		beaconClient:                  args.beaconClient,
		builderSecretKey:              args.sk,
		builderPublicKey:              pk,
		builderSigningDomain:          args.builderSigningDomain,
		builderResubmitInterval:       args.builderBlockResubmitInterval,
		discardRevertibleTxOnErr:      args.discardRevertibleTxOnErr,
		submissionOffsetFromEndOfSlot: args.submissionOffsetFromEndOfSlot,

		limiter:       args.limiter,
		slotCtx:       slotCtx,
		slotCtxCancel: slotCtxCancel,

		stop: make(chan struct{}, 1),
	}, nil
}

func (b *Builder) Start() error {
	// Start regular payload attributes updates
	go func() {
		c := make(chan types.BuilderPayloadAttributes)
		go b.beaconClient.SubscribeToPayloadAttributesEvents(c)

		currentSlot := uint64(0)

		for {
			select {
			case <-b.stop:
				return
			case payloadAttributes := <-c:
				// Right now we are building only on a single head. This might change in the future!
				if payloadAttributes.Slot < currentSlot {
					continue
				} else if payloadAttributes.Slot == currentSlot {
					// Subsequent sse events should only be canonical!
					if !b.ignoreLatePayloadAttributes {
						err := b.OnPayloadAttribute(&payloadAttributes)
						if err != nil {
							log.Error("error with builder processing on payload attribute",
								"latestSlot", currentSlot,
								"processedSlot", payloadAttributes.Slot,
								"headHash", payloadAttributes.HeadHash.String(),
								"error", err)
						}
					}
				} else if payloadAttributes.Slot > currentSlot {
					currentSlot = payloadAttributes.Slot
					err := b.OnPayloadAttribute(&payloadAttributes)
					if err != nil {
						log.Error("error with builder processing on payload attribute",
							"latestSlot", currentSlot,
							"processedSlot", payloadAttributes.Slot,
							"headHash", payloadAttributes.HeadHash.String(),
							"error", err)
					}
				}
			}
		}
	}()

	return b.relay.Start()
}

func (b *Builder) Stop() error {
	close(b.stop)
	return nil
}

func (b *Builder) onSealedBlock(block *types.Block, blockValue *big.Int, ordersClosedAt, sealedAt time.Time,
	commitedBundles, allBundles []types.SimulatedBundle, usedSbundles []types.UsedSBundle,
	proposerPubkey phase0.BLSPubKey, vd ValidatorData, attrs *types.BuilderPayloadAttributes) error {
	if b.eth.Config().IsShanghai(block.Time()) {
		if err := b.submitCapellaBlock(block, blockValue, ordersClosedAt, sealedAt, commitedBundles, allBundles, usedSbundles, proposerPubkey, vd, attrs); err != nil {
			return err
		}
	} else {
		if err := b.submitBellatrixBlock(block, blockValue, ordersClosedAt, sealedAt, commitedBundles, allBundles, usedSbundles, proposerPubkey, vd, attrs); err != nil {
			return err
		}
	}

	log.Info("submitted block", "slot", attrs.Slot, "value", blockValue.String(), "parent", block.ParentHash,
		"hash", block.Hash(), "#commitedBundles", len(commitedBundles))

	return nil
}

func (b *Builder) submitBellatrixBlock(block *types.Block, blockValue *big.Int, ordersClosedAt, sealedAt time.Time,
	commitedBundles, allBundles []types.SimulatedBundle, usedSbundles []types.UsedSBundle,
	proposerPubkey phase0.BLSPubKey, vd ValidatorData, attrs *types.BuilderPayloadAttributes) error {
	executableData := engine.BlockToExecutableData(block, blockValue)
	payload, err := executableDataToExecutionPayload(executableData.ExecutionPayload)
	if err != nil {
		log.Error("could not format execution payload", "err", err)
		return err
	}

	value, overflow := uint256.FromBig(blockValue)
	if overflow {
		log.Error("could not set block value due to value overflow")
		return err
	}

	blockBidMsg := apiv1.BidTrace{
		Slot:                 attrs.Slot,
		ParentHash:           payload.ParentHash,
		BlockHash:            payload.BlockHash,
		BuilderPubkey:        b.builderPublicKey,
		ProposerPubkey:       proposerPubkey,
		ProposerFeeRecipient: vd.FeeRecipient,
		GasLimit:             executableData.ExecutionPayload.GasLimit,
		GasUsed:              executableData.ExecutionPayload.GasUsed,
		Value:                value,
	}

	signature, err := ssz.SignMessage(&blockBidMsg, b.builderSigningDomain, b.builderSecretKey)
	if err != nil {
		log.Error("could not sign builder bid", "err", err)
		return err
	}

	blockSubmitReq := bellatrixapi.SubmitBlockRequest{
		Signature:        signature,
		Message:          &blockBidMsg,
		ExecutionPayload: payload,
	}

	if b.dryRun {
		err = b.validator.ValidateBuilderSubmissionV1(&blockvalidation.BuilderBlockValidationRequest{SubmitBlockRequest: blockSubmitReq, RegisteredGasLimit: vd.GasLimit})
		if err != nil {
			log.Error("could not validate bellatrix block", "err", err)
		}
	} else {
		go b.ds.ConsumeBuiltBlock(block, blockValue, ordersClosedAt, sealedAt, commitedBundles, allBundles, usedSbundles, &blockBidMsg)
		err = b.relay.SubmitBlock(&blockSubmitReq, vd)
		if err != nil {
			log.Error("could not submit bellatrix block", "err", err, "#commitedBundles", len(commitedBundles))
			return err
		}
	}

	log.Info("submitted bellatrix block", "slot", blockBidMsg.Slot, "value", blockBidMsg.Value.String(), "parent", blockBidMsg.ParentHash, "hash", block.Hash(), "#commitedBundles", len(commitedBundles))

	return nil
}

func (b *Builder) submitCapellaBlock(block *types.Block, blockValue *big.Int, ordersClosedAt, sealedAt time.Time,
	commitedBundles, allBundles []types.SimulatedBundle, usedSbundles []types.UsedSBundle,
	proposerPubkey phase0.BLSPubKey, vd ValidatorData, attrs *types.BuilderPayloadAttributes) error {
	executableData := engine.BlockToExecutableData(block, blockValue)
	payload, err := executableDataToCapellaExecutionPayload(executableData.ExecutionPayload)
	if err != nil {
		log.Error("could not format execution payload", "err", err)
		return err
	}

	value, overflow := uint256.FromBig(blockValue)
	if overflow {
		log.Error("could not set block value due to value overflow")
		return err
	}

	blockBidMsg := apiv1.BidTrace{
		Slot:                 attrs.Slot,
		ParentHash:           payload.ParentHash,
		BlockHash:            payload.BlockHash,
		BuilderPubkey:        b.builderPublicKey,
		ProposerPubkey:       proposerPubkey,
		ProposerFeeRecipient: vd.FeeRecipient,
		GasLimit:             executableData.ExecutionPayload.GasLimit,
		GasUsed:              executableData.ExecutionPayload.GasUsed,
		Value:                value,
	}

	signature, err := ssz.SignMessage(&blockBidMsg, b.builderSigningDomain, b.builderSecretKey)
	if err != nil {
		log.Error("could not sign builder bid", "err", err)
		return err
	}

	blockSubmitReq := capellaapi.SubmitBlockRequest{
		Signature:        signature,
		Message:          &blockBidMsg,
		ExecutionPayload: payload,
	}

	if b.dryRun {
		err = b.validator.ValidateBuilderSubmissionV2(&blockvalidation.BuilderBlockValidationRequestV2{SubmitBlockRequest: blockSubmitReq, RegisteredGasLimit: vd.GasLimit})
		if err != nil {
			log.Error("could not validate block for capella", "err", err)
		}
	} else {
		go b.ds.ConsumeBuiltBlock(block, blockValue, ordersClosedAt, sealedAt, commitedBundles, allBundles, usedSbundles, &blockBidMsg)
		err = b.relay.SubmitBlockCapella(&blockSubmitReq, vd)
		if err != nil {
			log.Error("could not submit capella block", "err", err, "#commitedBundles", len(commitedBundles))
			return err
		}
	}

	log.Info("submitted capella block", "slot", blockBidMsg.Slot, "value", blockBidMsg.Value.String(), "parent", blockBidMsg.ParentHash, "hash", block.Hash(), "#commitedBundles", len(commitedBundles))
	return nil
}

func (b *Builder) OnPayloadAttribute(attrs *types.BuilderPayloadAttributes) error {
	if attrs == nil {
		return nil
	}

	vd, err := b.relay.GetValidatorForSlot(attrs.Slot)
	if err != nil {
		return fmt.Errorf("could not get validator while submitting block for slot %d - %w", attrs.Slot, err)
	}

	attrs.SuggestedFeeRecipient = [20]byte(vd.FeeRecipient)
	attrs.GasLimit = vd.GasLimit

	proposerPubkey, err := utils.HexToPubkey(string(vd.Pubkey))
	if err != nil {
		return fmt.Errorf("could not parse pubkey (%s) - %w", vd.Pubkey, err)
	}

	if !b.eth.Synced() {
		return errors.New("backend not Synced")
	}

	parentBlock := b.eth.GetBlockByHash(attrs.HeadHash)
	if parentBlock == nil {
		return fmt.Errorf("parent block hash not found in block tree given head block hash %s", attrs.HeadHash)
	}

	b.slotMu.Lock()
	defer b.slotMu.Unlock()

	if attrs.Equal(&b.slotAttrs) {
		log.Debug("ignoring known payload attribute", "slot", attrs.Slot, "hash", attrs.HeadHash)
		return nil
	}

	if b.slotCtxCancel != nil {
		b.slotCtxCancel()
	}

	slotCtx, slotCtxCancel := context.WithTimeout(context.Background(), 12*time.Second)
	b.slotAttrs = *attrs
	b.slotCtx = slotCtx
	b.slotCtxCancel = slotCtxCancel

	go b.runBuildingJob(b.slotCtx, proposerPubkey, vd, attrs)
	return nil
}

type blockQueueEntry struct {
	block           *types.Block
	blockValue      *big.Int
	ordersCloseTime time.Time
	sealedAt        time.Time
	commitedBundles []types.SimulatedBundle
	allBundles      []types.SimulatedBundle
	usedSbundles    []types.UsedSBundle
}

func (b *Builder) runBuildingJob(slotCtx context.Context, proposerPubkey phase0.BLSPubKey, vd ValidatorData, attrs *types.BuilderPayloadAttributes) {
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

		queueMu                sync.Mutex
		queueLastSubmittedHash common.Hash
		queueBestEntry         blockQueueEntry
	)

	log.Debug("runBuildingJob", "slot", attrs.Slot, "parent", attrs.HeadHash, "payloadTimestamp", uint64(attrs.Timestamp))

	submitBestBlock := func() {
		queueMu.Lock()
		if queueBestEntry.block.Hash() != queueLastSubmittedHash {
			err := b.onSealedBlock(queueBestEntry.block, queueBestEntry.blockValue, queueBestEntry.ordersCloseTime, queueBestEntry.sealedAt,
				queueBestEntry.commitedBundles, queueBestEntry.allBundles, queueBestEntry.usedSbundles, proposerPubkey, vd, attrs)

			if err != nil {
				log.Error("could not run sealed block hook", "err", err)
			} else {
				queueLastSubmittedHash = queueBestEntry.block.Hash()
			}
		}
		queueMu.Unlock()
	}

	// Avoid submitting early into a given slot. For example if slots have 12 second interval, submissions should
	// not begin until 8 seconds into the slot.
	slotTime := time.Unix(int64(attrs.Timestamp), 0).UTC()
	slotSubmitStartTime := slotTime.Add(-b.submissionOffsetFromEndOfSlot)

	// Empties queue, submits the best block for current job with rate limit (global for all jobs)
	go runResubmitLoop(ctx, b.limiter, queueSignal, submitBestBlock, slotSubmitStartTime)

	// Populates queue with submissions that increase block profit
	blockHook := func(block *types.Block, blockValue *big.Int, ordersCloseTime time.Time,
		committedBundles, allBundles []types.SimulatedBundle, usedSbundles []types.UsedSBundle,
	) {
		if ctx.Err() != nil {
			return
		}

		sealedAt := time.Now()

		queueMu.Lock()
		defer queueMu.Unlock()
		if block.Hash() != queueLastSubmittedHash {
			queueBestEntry = blockQueueEntry{
				block:           block,
				blockValue:      new(big.Int).Set(blockValue),
				ordersCloseTime: ordersCloseTime,
				sealedAt:        sealedAt,
				commitedBundles: committedBundles,
				allBundles:      allBundles,
				usedSbundles:    usedSbundles,
			}

			select {
			case queueSignal <- struct{}{}:
			default:
			}
		}
	}

	// resubmits block builder requests every builderBlockResubmitInterval
	runRetryLoop(ctx, b.builderResubmitInterval, func() {
		log.Debug("retrying BuildBlock",
			"slot", attrs.Slot,
			"parent", attrs.HeadHash,
			"resubmit-interval", b.builderResubmitInterval.String())
		err := b.eth.BuildBlock(attrs, blockHook)
		if err != nil {
			log.Warn("Failed to build block", "err", err)
		}
	})
}

func executableDataToExecutionPayload(data *engine.ExecutableData) (*bellatrix.ExecutionPayload, error) {
	transactionData := make([]bellatrix.Transaction, len(data.Transactions))
	for i, tx := range data.Transactions {
		transactionData[i] = bellatrix.Transaction(tx)
	}

	baseFeePerGas := new(boostTypes.U256Str)
	err := baseFeePerGas.FromBig(data.BaseFeePerGas)
	if err != nil {
		return nil, err
	}

	return &bellatrix.ExecutionPayload{
		ParentHash:    [32]byte(data.ParentHash),
		FeeRecipient:  [20]byte(data.FeeRecipient),
		StateRoot:     [32]byte(data.StateRoot),
		ReceiptsRoot:  [32]byte(data.ReceiptsRoot),
		LogsBloom:     types.BytesToBloom(data.LogsBloom),
		PrevRandao:    [32]byte(data.Random),
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

func executableDataToCapellaExecutionPayload(data *engine.ExecutableData) (*capella.ExecutionPayload, error) {
	transactionData := make([]bellatrix.Transaction, len(data.Transactions))
	for i, tx := range data.Transactions {
		transactionData[i] = bellatrix.Transaction(tx)
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
		StateRoot:     [32]byte(data.StateRoot),
		ReceiptsRoot:  [32]byte(data.ReceiptsRoot),
		LogsBloom:     types.BytesToBloom(data.LogsBloom),
		PrevRandao:    [32]byte(data.Random),
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
