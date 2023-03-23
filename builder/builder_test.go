package builder

import (
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/flashbotsextra"
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
		gvsVd: ValidatorData{
			Pubkey:       PubkeyHex(testBeacon.validator.Pk.String()),
			FeeRecipient: feeRecipient,
			GasLimit:     10,
		},
	}

	sk, err := bls.SecretKeyFromBytes(hexutil.MustDecode("0x31ee185dad1220a8c88ca5275e64cf5a5cb09cb621cb30df52c9bee8fbaaf8d7"))
	require.NoError(t, err)

	bDomain := boostTypes.ComputeDomain(boostTypes.DomainTypeAppBuilder, [4]byte{0x02, 0x0, 0x0, 0x0}, boostTypes.Hash{})

	testExecutableData := &engine.ExecutableData{
		ParentHash:   common.Hash{0x02, 0x03},
		FeeRecipient: common.Address(feeRecipient),
		StateRoot:    common.Hash{0x07, 0x16},
		ReceiptsRoot: common.Hash{0x08, 0x20},
		LogsBloom:    types.Bloom{}.Bytes(),
		Number:       uint64(10),
		GasLimit:     uint64(50),
		GasUsed:      uint64(100),
		Timestamp:    uint64(105),
		ExtraData:    hexutil.MustDecode("0x0042fafc"),

		BaseFeePerGas: big.NewInt(16),

		BlockHash:    common.HexToHash("0xca4147f0d4150183ece9155068f34ee3c375448814e4ca557d482b1d40ee5407"),
		Transactions: [][]byte{},
	}

	testBlock, err := engine.ExecutableDataToBlock(*testExecutableData)
	require.NoError(t, err)

	testPayloadAttributes := &types.BuilderPayloadAttributes{
		Timestamp:             hexutil.Uint64(104),
		Random:                common.Hash{0x05, 0x10},
		SuggestedFeeRecipient: common.Address{0x04, 0x10},
		GasLimit:              uint64(21),
		Slot:                  uint64(25),
	}

	testEthService := &testEthereumService{synced: true, testExecutableData: testExecutableData, testBlock: testBlock, testBlockValue: big.NewInt(10)}

	builder := NewBuilder(sk, flashbotsextra.NilDbService{}, &testRelay, bDomain, testEthService, false, nil, &testBeacon)
	builder.Start()
	defer builder.Stop()

	err = builder.OnPayloadAttribute(testPayloadAttributes)
	require.NoError(t, err)
	time.Sleep(time.Second * 3)

	require.NotNil(t, testRelay.submittedMsg)
	expectedProposerPubkey, err := boostTypes.HexToPubkey(testBeacon.validator.Pk.String())
	require.NoError(t, err)

	expectedMessage := boostTypes.BidTrace{
		Slot:                 uint64(25),
		ParentHash:           boostTypes.Hash{0x02, 0x03},
		BuilderPubkey:        builder.builderPublicKey,
		ProposerPubkey:       expectedProposerPubkey,
		ProposerFeeRecipient: feeRecipient,
		GasLimit:             uint64(50),
		GasUsed:              uint64(100),
		Value:                boostTypes.U256Str{0x0a},
	}
	expectedMessage.BlockHash.FromSlice(hexutil.MustDecode("0xca4147f0d4150183ece9155068f34ee3c375448814e4ca557d482b1d40ee5407")[:])

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
		BlockHash:     expectedMessage.BlockHash,
		Transactions:  []hexutil.Bytes{},
	}

	require.Equal(t, expectedExecutionPayload, *testRelay.submittedMsg.ExecutionPayload)

	expectedSignature, err := boostTypes.HexToSignature("0xad09f171b1da05636acfc86778c319af69e39c79515d44bdfed616ba2ef677ffd4d155d87b3363c6bae651ce1e92786216b75f1ac91dd65f3b1d1902bf8485e742170732dd82ffdf4decb0151eeb7926dd053efa9794b2ebed1a203e62bb13e9")

	require.NoError(t, err)
	require.Equal(t, expectedSignature, testRelay.submittedMsg.Signature)

	require.Equal(t, uint64(25), testRelay.requestedSlot)

	// Clear the submitted message and check that the job will be ran again and but a new message will not be submitted since the hash is the same
	testEthService.testBlockValue = big.NewInt(10)

	testRelay.submittedMsg = nil
	time.Sleep(2200 * time.Millisecond)
	require.Nil(t, testRelay.submittedMsg)

	// Change the hash, expect to get the block
	testExecutableData.ExtraData = hexutil.MustDecode("0x0042fafd")
	testExecutableData.BlockHash = common.HexToHash("0x0579b1aaca5c079c91e5774bac72c7f9bc2ddf2b126e9c632be68a1cb8f3fc71")
	testBlock, err = engine.ExecutableDataToBlock(*testExecutableData)
	testEthService.testBlockValue = big.NewInt(10)
	require.NoError(t, err)
	testEthService.testBlock = testBlock

	time.Sleep(2200 * time.Millisecond)
	require.NotNil(t, testRelay.submittedMsg)
}
