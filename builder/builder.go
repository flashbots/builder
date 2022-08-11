package builder

import (
	"errors"
	_ "os"

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
}

type Builder struct {
	beaconClient IBeaconClient
	relay        IRelay
	eth          IEthereumService

	builderSecretKey     *bls.SecretKey
	builderPublicKey     boostTypes.PublicKey
	builderSigningDomain boostTypes.Domain
}

func NewBuilder(sk *bls.SecretKey, bc IBeaconClient, relay IRelay, builderSigningDomain boostTypes.Domain, eth IEthereumService) *Builder {
	pkBytes := bls.PublicKeyFromSecretKey(sk).Compress()
	pk := boostTypes.PublicKey{}
	pk.FromSlice(pkBytes)

	return &Builder{
		beaconClient:     bc,
		relay:            relay,
		eth:              eth,
		builderSecretKey: sk,
		builderPublicKey: pk,

		builderSigningDomain: builderSigningDomain,
	}
}

func (b *Builder) OnPayloadAttribute(attrs *BuilderPayloadAttributes) error {
	if attrs != nil {
		vd, err := b.relay.GetValidatorForSlot(attrs.Slot)
		if err != nil {
			log.Info("could not get validator while submitting block", "err", err, "slot", attrs.Slot)
			return err
		}

		attrs.SuggestedFeeRecipient = [20]byte(vd.FeeRecipient)
		attrs.GasLimit = vd.GasLimit

		if b.eth.Synced() {
			parentBlock := b.eth.GetBlockByHash(attrs.HeadHash)
			if parentBlock == nil {
				log.Info("Block hash not found in blocktree", "head block hash", attrs.HeadHash)
				return err
			}

			executableData, block := b.eth.BuildBlock(attrs)
			if executableData == nil || block == nil {
				log.Error("did not receive the payload")
				return errors.New("could not build block")
			}
			payload, err := executableDataToExecutionPayload(executableData)
			if err != nil {
				log.Error("could not format execution payload", "err", err)
				return err
			}

			pubkey, err := boostTypes.HexToPubkey(string(vd.Pubkey))
			if err != nil {
				log.Error("could not parse pubkey", "err", err, "pubkey", vd.Pubkey)
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
				ProposerPubkey:       pubkey,
				ProposerFeeRecipient: boostTypes.Address(attrs.SuggestedFeeRecipient),
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

			err = b.relay.SubmitBlock(&blockSubmitReq)
			if err != nil {
				log.Error("could not submit block", "err", err)
				return err
			}
		}
	}
	return nil
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
