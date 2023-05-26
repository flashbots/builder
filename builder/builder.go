package builder

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	_ "os"
	"sync"
	"time"

	capellaapi "github.com/attestantio/go-builder-client/api/capella"
	apiv1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	blockvalidation "github.com/ethereum/go-ethereum/eth/block-validation"
	"github.com/ethereum/go-ethereum/flashbotsextra"
	"github.com/ethereum/go-ethereum/log"
	"github.com/flashbots/go-boost-utils/bls"
	boostTypes "github.com/flashbots/go-boost-utils/types"
	"github.com/holiman/uint256"
	"golang.org/x/time/rate"
)

const (
	RateLimitIntervalDefault     = 500 * time.Millisecond
	RateLimitBurstDefault        = 10
	BlockResubmitIntervalDefault = 500 * time.Millisecond

	SubmissionDelaySecondsDefault = 4 * time.Second
)

type PubkeyHex string

type ValidatorData struct {
	Pubkey       PubkeyHex
	FeeRecipient boostTypes.Address
	GasLimit     uint64
}

type IRelay interface {
	SubmitBlock(msg *boostTypes.BuilderSubmitBlockRequest, vd ValidatorData) error
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
	builderPublicKey            boostTypes.PublicKey
	builderSigningDomain        boostTypes.Domain
	builderResubmitInterval     time.Duration

	limiter *rate.Limiter

	slotMu        sync.Mutex
	slotAttrs     types.BuilderPayloadAttributes
	slotCtx       context.Context
	slotCtxCancel context.CancelFunc

	stop chan struct{}
}

// BuilderArgs is a struct that contains all the arguments needed to create a new Builder
type BuilderArgs struct {
	sk                           *bls.SecretKey
	ds                           flashbotsextra.IDatabaseService
	relay                        IRelay
	builderSigningDomain         boostTypes.Domain
	builderBlockResubmitInterval time.Duration
	eth                          IEthereumService
	dryRun                       bool
	ignoreLatePayloadAttributes  bool
	validator                    *blockvalidation.BlockValidationAPI
	beaconClient                 IBeaconClient

	limiter *rate.Limiter
}

func NewBuilder(args BuilderArgs) *Builder {
	pkBytes := bls.PublicKeyFromSecretKey(args.sk).Compress()
	pk := boostTypes.PublicKey{}
	pk.FromSlice(pkBytes)

	if args.limiter == nil {
		args.limiter = rate.NewLimiter(rate.Every(RateLimitIntervalDefault), RateLimitBurstDefault)
	}

	if args.builderBlockResubmitInterval == 0 {
		args.builderBlockResubmitInterval = BlockResubmitIntervalDefault
	}

	slotCtx, slotCtxCancel := context.WithCancel(context.Background())
	return &Builder{
		ds:                          args.ds,
		relay:                       args.relay,
		eth:                         args.eth,
		dryRun:                      args.dryRun,
		ignoreLatePayloadAttributes: args.ignoreLatePayloadAttributes,
		validator:                   args.validator,
		beaconClient:                args.beaconClient,
		builderSecretKey:            args.sk,
		builderPublicKey:            pk,
		builderSigningDomain:        args.builderSigningDomain,
		builderResubmitInterval:     args.builderBlockResubmitInterval,

		limiter:       args.limiter,
		slotCtx:       slotCtx,
		slotCtxCancel: slotCtxCancel,

		stop: make(chan struct{}, 1),
	}
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

func (b *Builder) onSealedBlock(block *types.Block, blockValue *big.Int, ordersClosedAt, sealedAt time.Time, commitedBundles, allBundles []types.SimulatedBundle, proposerPubkey boostTypes.PublicKey, vd ValidatorData, attrs *types.BuilderPayloadAttributes) error {
	if b.eth.Config().IsShanghai(block.Time()) {
		if err := b.submitCapellaBlock(block, blockValue, ordersClosedAt, sealedAt, commitedBundles, allBundles, proposerPubkey, vd, attrs); err != nil {
			return err
		}
	} else {
		if err := b.submitBellatrixBlock(block, blockValue, ordersClosedAt, sealedAt, commitedBundles, allBundles, proposerPubkey, vd, attrs); err != nil {
			return err
		}
	}

	log.Info("submitted block", "slot", attrs.Slot, "value", blockValue.String(), "parent", block.ParentHash,
		"hash", block.Hash(), "#commitedBundles", len(commitedBundles))

	return nil
}

func (b *Builder) submitBellatrixBlock(block *types.Block, blockValue *big.Int, ordersClosedAt, sealedAt time.Time, commitedBundles, allBundles []types.SimulatedBundle, proposerPubkey boostTypes.PublicKey, vd ValidatorData, attrs *types.BuilderPayloadAttributes) error {
	executableData := engine.BlockToExecutableData(block, blockValue)
	payload, err := executableDataToExecutionPayload(executableData.ExecutionPayload)
	if err != nil {
		log.Error("could not format execution payload", "err", err)
		return err
	}

	value := new(boostTypes.U256Str)
	err = value.FromBig(blockValue)
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
		GasLimit:             executableData.ExecutionPayload.GasLimit,
		GasUsed:              executableData.ExecutionPayload.GasUsed,
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
			log.Error("could not validate bellatrix block", "err", err)
		}
	} else {
		go b.ds.ConsumeBuiltBlock(block, blockValue, ordersClosedAt, sealedAt, commitedBundles, allBundles, &blockBidMsg)
		err = b.relay.SubmitBlock(&blockSubmitReq, vd)
		if err != nil {
			log.Error("could not submit bellatrix block", "err", err, "#commitedBundles", len(commitedBundles))
			return err
		}
	}

	log.Info("submitted bellatrix block", "slot", blockBidMsg.Slot, "value", blockBidMsg.Value.String(), "parent", blockBidMsg.ParentHash, "hash", block.Hash(), "#commitedBundles", len(commitedBundles))

	return nil
}

func (b *Builder) submitCapellaBlock(block *types.Block, blockValue *big.Int, ordersClosedAt, sealedAt time.Time, commitedBundles, allBundles []types.SimulatedBundle, proposerPubkey boostTypes.PublicKey, vd ValidatorData, attrs *types.BuilderPayloadAttributes) error {
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
		BuilderPubkey:        phase0.BLSPubKey(b.builderPublicKey),
		ProposerPubkey:       phase0.BLSPubKey(proposerPubkey),
		ProposerFeeRecipient: bellatrix.ExecutionAddress(vd.FeeRecipient),
		GasLimit:             executableData.ExecutionPayload.GasLimit,
		GasUsed:              executableData.ExecutionPayload.GasUsed,
		Value:                value,
	}

	boostBidTrace, err := convertBidTrace(blockBidMsg)
	if err != nil {
		log.Error("could not convert bid trace", "err", err)
		return err
	}

	signature, err := boostTypes.SignMessage(&blockBidMsg, b.builderSigningDomain, b.builderSecretKey)
	if err != nil {
		log.Error("could not sign builder bid", "err", err)
		return err
	}

	blockSubmitReq := capellaapi.SubmitBlockRequest{
		Signature:        phase0.BLSSignature(signature),
		Message:          &blockBidMsg,
		ExecutionPayload: payload,
	}

	if b.dryRun {
		err = b.validator.ValidateBuilderSubmissionV2(&blockvalidation.BuilderBlockValidationRequestV2{SubmitBlockRequest: blockSubmitReq, RegisteredGasLimit: vd.GasLimit})
		if err != nil {
			log.Error("could not validate block for capella", "err", err)
		}
	} else {
		go b.ds.ConsumeBuiltBlock(block, blockValue, ordersClosedAt, sealedAt, commitedBundles, allBundles, &boostBidTrace)
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

	proposerPubkey, err := boostTypes.HexToPubkey(string(vd.Pubkey))
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
}

func (b *Builder) runBuildingJob(slotCtx context.Context, proposerPubkey boostTypes.PublicKey, vd ValidatorData, attrs *types.BuilderPayloadAttributes) {
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
			err := b.onSealedBlock(queueBestEntry.block, queueBestEntry.blockValue, queueBestEntry.ordersCloseTime, queueBestEntry.sealedAt, queueBestEntry.commitedBundles, queueBestEntry.allBundles, proposerPubkey, vd, attrs)

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
	slotSubmitStartTime := slotTime.Add(-SubmissionDelaySecondsDefault)

	// Empties queue, submits the best block for current job with rate limit (global for all jobs)
	go runResubmitLoop(ctx, b.limiter, queueSignal, submitBestBlock, slotSubmitStartTime)

	// Populates queue with submissions that increase block profit
	blockHook := func(block *types.Block, blockValue *big.Int, ordersCloseTime time.Time,
		committedBundles, allBundles []types.SimulatedBundle,
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

func executableDataToExecutionPayload(data *engine.ExecutableData) (*boostTypes.ExecutionPayload, error) {
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
		LogsBloom:     boostTypes.Bloom(types.BytesToBloom(data.LogsBloom)),
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

func convertBidTrace(bidTrace apiv1.BidTrace) (boostTypes.BidTrace, error) {
	value := new(boostTypes.U256Str)
	err := value.FromBig(bidTrace.Value.ToBig())
	if err != nil {
		return boostTypes.BidTrace{}, err
	}

	return boostTypes.BidTrace{
		Slot:                 bidTrace.Slot,
		ParentHash:           boostTypes.Hash(bidTrace.ParentHash),
		BlockHash:            boostTypes.Hash(bidTrace.BlockHash),
		BuilderPubkey:        boostTypes.PublicKey(bidTrace.BuilderPubkey),
		ProposerPubkey:       boostTypes.PublicKey(bidTrace.ProposerPubkey),
		ProposerFeeRecipient: boostTypes.Address(bidTrace.ProposerFeeRecipient),
		GasLimit:             bidTrace.GasLimit,
		GasUsed:              bidTrace.GasUsed,
		Value:                *value,
	}, nil
}
