package builder

import (
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/beacon"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/flashbots/go-boost-utils/bls"
	boostTypes "github.com/flashbots/go-boost-utils/types"
	"github.com/stretchr/testify/require"
)

func TestOnPayloadAttributes(t *testing.T) {
	vsk, err := bls.SecretKeyFromBytes(hexutil.MustDecode("0x370bb8c1a6e62b2882f6ec76762a67b39609002076b95aae5b023997cf9b2dc9"))
	require.NoError(t, err)
	validator := &ValidatorPrivateData{
		sk: vsk,
		Pk: hexutil.MustDecode("0xb67d2c11bcab8c4394fc2faa9601d0b99c7f4b37e14911101da7d97077917862eed4563203d34b91b5cf0aa44d6cfa05"),
	}

	testBeacon := testBeaconClient{
		validator: validator,
		slot:      56,
	}

	feeRecipient, _ := boostTypes.HexToAddress("0xabcf8e0d4e9587369b2301d0790347320302cc00")
	testRelay := testRelay{
		validator: ValidatorData{
			Pubkey:       PubkeyHex(testBeacon.validator.Pk.String()),
			FeeRecipient: feeRecipient,
			GasLimit:     10,
			Timestamp:    15,
		},
	}

	sk, err := bls.SecretKeyFromBytes(hexutil.MustDecode("0x31ee185dad1220a8c88ca5275e64cf5a5cb09cb621cb30df52c9bee8fbaaf8d7"))
	require.NoError(t, err)

	bDomain := boostTypes.ComputeDomain(boostTypes.DomainTypeAppBuilder, [4]byte{0x02, 0x0, 0x0, 0x0}, boostTypes.Hash{})

	testExecutableData := &beacon.ExecutableDataV1{
		ParentHash:   common.Hash{0x02, 0x03},
		FeeRecipient: common.Address(feeRecipient),
		StateRoot:    common.Hash{0x07, 0x16},
		ReceiptsRoot: common.Hash{0x08, 0x20},
		LogsBloom:    hexutil.MustDecode("0x000000000000000000000000000000"),
		Number:       uint64(10),
		GasLimit:     uint64(50),
		GasUsed:      uint64(100),
		Timestamp:    uint64(105),
		ExtraData:    hexutil.MustDecode("0x0042fafc"),

		BaseFeePerGas: big.NewInt(16),

		BlockHash:    common.Hash{0x09, 0xff},
		Transactions: [][]byte{},
	}

	testBlock := &types.Block{
		Profit: big.NewInt(10),
	}

	testPayloadAttributes := &BuilderPayloadAttributes{
		Timestamp:             hexutil.Uint64(104),
		Random:                common.Hash{0x05, 0x10},
		SuggestedFeeRecipient: common.Address{0x04, 0x10},
		GasLimit:              uint64(21),
		Slot:                  uint64(25),
	}

	testEthService := &testEthereumService{synced: true, testExecutableData: testExecutableData, testBlock: testBlock}

	builder := NewBuilder(sk, &testBeacon, &testRelay, bDomain, testEthService)

	builder.OnPayloadAttribute(testPayloadAttributes)

	require.NotNil(t, testRelay.submittedMsg)
	expectedProposerPubkey, err := boostTypes.HexToPubkey(testBeacon.validator.Pk.String())
	require.NoError(t, err)

	expectedMessage := boostTypes.BidTrace{
		Slot:                 uint64(25),
		ParentHash:           boostTypes.Hash{0x02, 0x03},
		BlockHash:            boostTypes.Hash{0x09, 0xff},
		BuilderPubkey:        builder.builderPublicKey,
		ProposerPubkey:       expectedProposerPubkey,
		ProposerFeeRecipient: feeRecipient,
		GasLimit:             uint64(50),
		GasUsed:              uint64(100),
		Value:                boostTypes.U256Str{0x0a},
	}

	require.Equal(t, expectedMessage, *testRelay.submittedMsg.Message)

	expectedExecutionPayload := boostTypes.ExecutionPayload{
		ParentHash:    [32]byte(testExecutableData.ParentHash),
		FeeRecipient:  feeRecipient,
		StateRoot:     [32]byte(testExecutableData.StateRoot),
		ReceiptsRoot:  [32]byte(testExecutableData.ReceiptsRoot),
		LogsBloom:     [256]byte{},
		Random:        [32]byte(testExecutableData.Random),
		BlockNumber:   testExecutableData.Number,
		GasLimit:      testExecutableData.GasLimit,
		GasUsed:       testExecutableData.GasUsed,
		Timestamp:     testExecutableData.Timestamp,
		ExtraData:     hexutil.MustDecode("0x0042fafc"),
		BaseFeePerGas: boostTypes.U256Str{0x10},
		BlockHash:     boostTypes.Hash{0x09, 0xff},
		Transactions:  []hexutil.Bytes{},
	}

	require.Equal(t, expectedExecutionPayload, *testRelay.submittedMsg.ExecutionPayload)

	expectedSignature, err := boostTypes.HexToSignature("0xb086abc231a515559128122a6618ad316a76195ad39aa28195c9e8921b98561ca4fd12e2e1ea8d50d8e22f7e36d42ee1084fef26672beceda7650a87061e412d7742705077ac3af3ca1a1c3494eccb22fe7c234fd547a285ba699ff87f0e7759")

	require.NoError(t, err)
	require.Equal(t, expectedSignature, testRelay.submittedMsg.Signature)

	require.Equal(t, uint64(25), testRelay.requestedSlot)

	// Clear the submitted message and check that the job will be ran again and but a new message will not be submitted since the profit is the same
	testRelay.submittedMsg = nil
	time.Sleep(1200 * time.Millisecond)
	require.Nil(t, testRelay.submittedMsg)

	// Up the profit, expect to get the block
	testEthService.testBlock.Profit.SetInt64(11)
	time.Sleep(1200 * time.Millisecond)
	require.NotNil(t, testRelay.submittedMsg)
}
