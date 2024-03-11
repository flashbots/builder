package blockvalidation

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/attestantio/go-builder-client/api"
	builderApiBellatrix "github.com/attestantio/go-builder-client/api/bellatrix"
	builderApiCapella "github.com/attestantio/go-builder-client/api/capella"
	builderApiDeneb "github.com/attestantio/go-builder-client/api/deneb"
	builderApiV1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus"
	beaconConsensus "github.com/ethereum/go-ethereum/consensus/beacon"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/eth/tracers/logger"
	"github.com/ethereum/go-ethereum/miner"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/triedb"
	boostTypes "github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/go-boost-utils/utils"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

/* Based on catalyst API tests */

var (
	// testKey is a private key to use for funding a tester account.
	testKey, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")

	// testAddr is the Ethereum address of the tester account.
	testAddr = crypto.PubkeyToAddress(testKey.PublicKey)

	testValidatorKey, _ = crypto.HexToECDSA("28c3cd61b687fdd03488e167a5d84f50269df2a4c29a2cfb1390903aa775c5d0")
	testValidatorAddr   = crypto.PubkeyToAddress(testValidatorKey.PublicKey)

	testBuilderKeyHex = "0bfbbbc68fefd990e61ba645efb84e0a62e94d5fff02c9b1da8eb45fea32b4e0"
	testBuilderKey, _ = crypto.HexToECDSA(testBuilderKeyHex)
	testBuilderAddr   = crypto.PubkeyToAddress(testBuilderKey.PublicKey)

	testBalance = big.NewInt(2e18)

	// This EVM code generates a log when the contract is created.
	logCode = common.Hex2Bytes("60606040525b7f24ec1d3ff24c2f6ff210738839dbc339cd45a5294d85c79361016243157aae7b60405180905060405180910390a15b600a8060416000396000f360606040526008565b00")
)

func TestValidateBuilderSubmissionV1(t *testing.T) {
	genesis, preMergeBlocks := generatePreMergeChain(20)
	os.Setenv("BUILDER_TX_SIGNING_KEY", "0x28c3cd61b687fdd03488e167a5d84f50269df2a4c29a2cfb1390903aa775c5d0")
	n, ethservice := startEthService(t, genesis, preMergeBlocks)
	ethservice.Merger().ReachTTD()
	defer n.Close()

	api := NewBlockValidationAPI(ethservice, nil, true, true)
	parent := preMergeBlocks[len(preMergeBlocks)-1]

	api.eth.APIBackend.Miner().SetEtherbase(testValidatorAddr)

	statedb, _ := ethservice.BlockChain().StateAt(parent.Root())
	nonce := statedb.GetNonce(testAddr)

	tx1, _ := types.SignTx(types.NewTransaction(nonce, common.Address{0x16}, big.NewInt(10), 21000, big.NewInt(2*params.InitialBaseFee), nil), types.LatestSigner(ethservice.BlockChain().Config()), testKey)
	ethservice.TxPool().Add([]*types.Transaction{tx1}, true, true, false)

	cc, _ := types.SignTx(types.NewContractCreation(nonce+1, new(big.Int), 1000000, big.NewInt(2*params.InitialBaseFee), logCode), types.LatestSigner(ethservice.BlockChain().Config()), testKey)
	ethservice.TxPool().Add([]*types.Transaction{cc}, true, true, false)

	baseFee := eip1559.CalcBaseFee(params.AllEthashProtocolChanges, preMergeBlocks[len(preMergeBlocks)-1].Header())
	tx2, _ := types.SignTx(types.NewTransaction(nonce+2, testAddr, big.NewInt(10), 21000, baseFee, nil), types.LatestSigner(ethservice.BlockChain().Config()), testKey)
	ethservice.TxPool().Add([]*types.Transaction{tx2}, true, true, false)

	execData, err := assembleBlock(api, parent.Hash(), &engine.PayloadAttributes{
		Timestamp:             parent.Time() + 5,
		SuggestedFeeRecipient: testValidatorAddr,
	})
	require.EqualValues(t, len(execData.Transactions), 4)
	require.NoError(t, err)

	payload, err := ExecutableDataToExecutionPayload(execData)
	require.NoError(t, err)

	proposerAddr := bellatrix.ExecutionAddress{}
	copy(proposerAddr[:], testValidatorAddr[:])

	blockRequest := &BuilderBlockValidationRequest{
		SubmitBlockRequest: builderApiBellatrix.SubmitBlockRequest{
			Signature: phase0.BLSSignature{},
			Message: &builderApiV1.BidTrace{
				ParentHash:           phase0.Hash32(execData.ParentHash),
				BlockHash:            phase0.Hash32(execData.BlockHash),
				ProposerFeeRecipient: proposerAddr,
				GasLimit:             execData.GasLimit,
				GasUsed:              execData.GasUsed,
			},
			ExecutionPayload: payload,
		},
		RegisteredGasLimit: execData.GasLimit,
	}

	blockRequest.Message.Value = uint256.NewInt(190526394825529)
	require.ErrorContains(t, api.ValidateBuilderSubmissionV1(blockRequest), "inaccurate payment")
	blockRequest.Message.Value = uint256.NewInt(149830884438530)
	require.NoError(t, api.ValidateBuilderSubmissionV1(blockRequest))

	blockRequest.Message.GasLimit += 1
	blockRequest.ExecutionPayload.GasLimit += 1
	updatePayloadHash(t, blockRequest)

	require.ErrorContains(t, api.ValidateBuilderSubmissionV1(blockRequest), "incorrect gas limit set")

	blockRequest.Message.GasLimit -= 1
	blockRequest.ExecutionPayload.GasLimit -= 1
	updatePayloadHash(t, blockRequest)

	// TODO: test with contract calling blacklisted address
	// Test tx from blacklisted address
	api.accessVerifier = &AccessVerifier{
		blacklistedAddresses: map[common.Address]struct{}{
			testAddr: {},
		},
	}
	require.ErrorContains(t, api.ValidateBuilderSubmissionV1(blockRequest), "transaction from blacklisted address 0x71562b71999873DB5b286dF957af199Ec94617F7")

	// Test tx to blacklisted address
	api.accessVerifier = &AccessVerifier{
		blacklistedAddresses: map[common.Address]struct{}{
			{0x16}: {},
		},
	}
	require.ErrorContains(t, api.ValidateBuilderSubmissionV1(blockRequest), "transaction to blacklisted address 0x1600000000000000000000000000000000000000")

	api.accessVerifier = nil

	blockRequest.Message.GasUsed = 10
	require.ErrorContains(t, api.ValidateBuilderSubmissionV1(blockRequest), "incorrect GasUsed 10, expected 119990")
	blockRequest.Message.GasUsed = execData.GasUsed

	newTestKey, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f290")
	invalidTx, err := types.SignTx(types.NewTransaction(0, common.Address{}, new(big.Int).Mul(big.NewInt(2e18), big.NewInt(10)), 19000, big.NewInt(2*params.InitialBaseFee), nil), types.LatestSigner(ethservice.BlockChain().Config()), newTestKey)
	require.NoError(t, err)

	txData, err := invalidTx.MarshalBinary()
	require.NoError(t, err)
	execData.Transactions = append(execData.Transactions, txData)

	invalidPayload, err := ExecutableDataToExecutionPayload(execData)
	require.NoError(t, err)
	invalidPayload.GasUsed = execData.GasUsed
	copy(invalidPayload.ReceiptsRoot[:], hexutil.MustDecode("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")[:32])
	blockRequest.ExecutionPayload = invalidPayload
	updatePayloadHash(t, blockRequest)
	require.ErrorContains(t, api.ValidateBuilderSubmissionV1(blockRequest), "could not apply tx 4", "insufficient funds for gas * price + value")
}

func TestValidateBuilderSubmissionV2(t *testing.T) {
	genesis, preMergeBlocks := generatePreMergeChain(20)
	os.Setenv("BUILDER_TX_SIGNING_KEY", testBuilderKeyHex)
	time := preMergeBlocks[len(preMergeBlocks)-1].Time() + 5
	genesis.Config.ShanghaiTime = &time
	n, ethservice := startEthService(t, genesis, preMergeBlocks)
	ethservice.Merger().ReachTTD()
	defer n.Close()

	api := NewBlockValidationAPI(ethservice, nil, true, true)
	parent := preMergeBlocks[len(preMergeBlocks)-1]

	api.eth.APIBackend.Miner().SetEtherbase(testBuilderAddr)

	statedb, _ := ethservice.BlockChain().StateAt(parent.Root())
	nonce := statedb.GetNonce(testAddr)

	tx1, _ := types.SignTx(types.NewTransaction(nonce, common.Address{0x16}, big.NewInt(10), 21000, big.NewInt(2*params.InitialBaseFee), nil), types.LatestSigner(ethservice.BlockChain().Config()), testKey)
	ethservice.TxPool().Add([]*types.Transaction{tx1}, true, true, false)

	cc, _ := types.SignTx(types.NewContractCreation(nonce+1, new(big.Int), 1000000, big.NewInt(2*params.InitialBaseFee), logCode), types.LatestSigner(ethservice.BlockChain().Config()), testKey)
	ethservice.TxPool().Add([]*types.Transaction{cc}, true, true, false)

	baseFee := eip1559.CalcBaseFee(params.AllEthashProtocolChanges, preMergeBlocks[len(preMergeBlocks)-1].Header())
	tx2, _ := types.SignTx(types.NewTransaction(nonce+2, testAddr, big.NewInt(10), 21000, baseFee, nil), types.LatestSigner(ethservice.BlockChain().Config()), testKey)
	ethservice.TxPool().Add([]*types.Transaction{tx2}, true, true, false)

	withdrawals := []*types.Withdrawal{
		{
			Index:     0,
			Validator: 1,
			Amount:    100,
			Address:   testAddr,
		},
		{
			Index:     1,
			Validator: 1,
			Amount:    100,
			Address:   testAddr,
		},
	}

	execData, err := assembleBlock(api, parent.Hash(), &engine.PayloadAttributes{
		Timestamp:             parent.Time() + 5,
		Withdrawals:           withdrawals,
		SuggestedFeeRecipient: testValidatorAddr,
	})
	require.NoError(t, err)
	require.EqualValues(t, len(execData.Withdrawals), 2)
	require.EqualValues(t, len(execData.Transactions), 4)

	payload, err := ExecutableDataToExecutionPayloadV2(execData)
	require.NoError(t, err)

	proposerAddr := bellatrix.ExecutionAddress{}
	copy(proposerAddr[:], testValidatorAddr.Bytes())

	blockRequest := &BuilderBlockValidationRequestV2{
		SubmitBlockRequest: builderApiCapella.SubmitBlockRequest{
			Signature: phase0.BLSSignature{},
			Message: &builderApiV1.BidTrace{
				ParentHash:           phase0.Hash32(execData.ParentHash),
				BlockHash:            phase0.Hash32(execData.BlockHash),
				ProposerFeeRecipient: proposerAddr,
				GasLimit:             execData.GasLimit,
				GasUsed:              execData.GasUsed,
				// This value is actual profit + 1, validation should fail
				Value: uint256.NewInt(149842511727213),
			},
			ExecutionPayload: payload,
		},
		RegisteredGasLimit: execData.GasLimit,
	}

	require.ErrorContains(t, api.ValidateBuilderSubmissionV2(blockRequest), "inaccurate payment")
	blockRequest.Message.Value = uint256.NewInt(149842511727212)
	require.NoError(t, api.ValidateBuilderSubmissionV2(blockRequest))

	blockRequest.Message.GasLimit += 1
	blockRequest.ExecutionPayload.GasLimit += 1
	updatePayloadHashV2(t, blockRequest)

	require.ErrorContains(t, api.ValidateBuilderSubmissionV2(blockRequest), "incorrect gas limit set")

	blockRequest.Message.GasLimit -= 1
	blockRequest.ExecutionPayload.GasLimit -= 1
	updatePayloadHashV2(t, blockRequest)

	// TODO: test with contract calling blacklisted address
	// Test tx from blacklisted address
	api.accessVerifier = &AccessVerifier{
		blacklistedAddresses: map[common.Address]struct{}{
			testAddr: {},
		},
	}
	require.ErrorContains(t, api.ValidateBuilderSubmissionV2(blockRequest), "transaction from blacklisted address 0x71562b71999873DB5b286dF957af199Ec94617F7")

	// Test tx to blacklisted address
	api.accessVerifier = &AccessVerifier{
		blacklistedAddresses: map[common.Address]struct{}{
			{0x16}: {},
		},
	}
	require.ErrorContains(t, api.ValidateBuilderSubmissionV2(blockRequest), "transaction to blacklisted address 0x1600000000000000000000000000000000000000")

	api.accessVerifier = nil

	blockRequest.Message.GasUsed = 10
	require.ErrorContains(t, api.ValidateBuilderSubmissionV2(blockRequest), "incorrect GasUsed 10, expected 119996")
	blockRequest.Message.GasUsed = execData.GasUsed

	newTestKey, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f290")
	invalidTx, err := types.SignTx(types.NewTransaction(0, common.Address{}, new(big.Int).Mul(big.NewInt(2e18), big.NewInt(10)), 19000, big.NewInt(2*params.InitialBaseFee), nil), types.LatestSigner(ethservice.BlockChain().Config()), newTestKey)
	require.NoError(t, err)

	txData, err := invalidTx.MarshalBinary()
	require.NoError(t, err)
	execData.Transactions = append(execData.Transactions, txData)

	invalidPayload, err := ExecutableDataToExecutionPayloadV2(execData)
	require.NoError(t, err)
	invalidPayload.GasUsed = execData.GasUsed
	copy(invalidPayload.ReceiptsRoot[:], hexutil.MustDecode("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")[:32])
	blockRequest.ExecutionPayload = invalidPayload
	updatePayloadHashV2(t, blockRequest)
	require.ErrorContains(t, api.ValidateBuilderSubmissionV2(blockRequest), "could not apply tx 4", "insufficient funds for gas * price + value")
}

func TestValidateBuilderSubmissionV3(t *testing.T) {
	genesis, blocks := generateMergeChain(10, true)

	// Set cancun time to last block + 5 seconds
	time := blocks[len(blocks)-1].Time() + 5
	genesis.Config.ShanghaiTime = &time
	genesis.Config.CancunTime = &time
	os.Setenv("BUILDER_TX_SIGNING_KEY", testBuilderKeyHex)

	n, ethservice := startEthService(t, genesis, blocks)
	ethservice.Merger().ReachTTD()
	defer n.Close()

	api := NewBlockValidationAPI(ethservice, nil, true, false)
	parent := ethservice.BlockChain().CurrentHeader()

	api.eth.APIBackend.Miner().SetEtherbase(testBuilderAddr)

	statedb, _ := ethservice.BlockChain().StateAt(parent.Root)
	nonce := statedb.GetNonce(testAddr)

	tx1, _ := types.SignTx(types.NewTransaction(nonce, common.Address{0x16}, big.NewInt(10), 21000, big.NewInt(2*params.InitialBaseFee), nil), types.LatestSigner(ethservice.BlockChain().Config()), testKey)
	ethservice.TxPool().Add([]*types.Transaction{tx1}, true, true, false)

	cc, _ := types.SignTx(types.NewContractCreation(nonce+1, new(big.Int), 1000000, big.NewInt(2*params.InitialBaseFee), logCode), types.LatestSigner(ethservice.BlockChain().Config()), testKey)
	ethservice.TxPool().Add([]*types.Transaction{cc}, true, true, false)

	baseFee := eip1559.CalcBaseFee(params.AllEthashProtocolChanges, parent)
	tx2, _ := types.SignTx(types.NewTransaction(nonce+2, testAddr, big.NewInt(10), 21000, baseFee, nil), types.LatestSigner(ethservice.BlockChain().Config()), testKey)
	ethservice.TxPool().Add([]*types.Transaction{tx2}, true, true, false)

	withdrawals := []*types.Withdrawal{
		{
			Index:     0,
			Validator: 1,
			Amount:    100,
			Address:   testAddr,
		},
		{
			Index:     1,
			Validator: 1,
			Amount:    100,
			Address:   testAddr,
		},
	}

	execData, err := assembleBlock(api, parent.Hash(), &engine.PayloadAttributes{
		Timestamp:             parent.Time + 5,
		Withdrawals:           withdrawals,
		SuggestedFeeRecipient: testValidatorAddr,
		BeaconRoot:            &common.Hash{42},
	})
	require.NoError(t, err)
	require.EqualValues(t, len(execData.Withdrawals), 2)
	require.EqualValues(t, len(execData.Transactions), 4)

	payload, err := ExecutableDataToExecutionPayloadV3(execData)
	require.NoError(t, err)

	proposerAddr := bellatrix.ExecutionAddress{}
	copy(proposerAddr[:], testValidatorAddr.Bytes())

	blockRequest := &BuilderBlockValidationRequestV3{
		SubmitBlockRequest: builderApiDeneb.SubmitBlockRequest{
			Signature: phase0.BLSSignature{},
			Message: &builderApiV1.BidTrace{
				ParentHash:           phase0.Hash32(execData.ParentHash),
				BlockHash:            phase0.Hash32(execData.BlockHash),
				ProposerFeeRecipient: proposerAddr,
				GasLimit:             execData.GasLimit,
				GasUsed:              execData.GasUsed,
				// This value is actual profit + 1, validation should fail
				Value: uint256.NewInt(132912184722469),
			},
			ExecutionPayload: payload,
			BlobsBundle: &builderApiDeneb.BlobsBundle{
				Commitments: make([]deneb.KZGCommitment, 0),
				Proofs:      make([]deneb.KZGProof, 0),
				Blobs:       make([]deneb.Blob, 0),
			},
		},
		RegisteredGasLimit:    execData.GasLimit,
		ParentBeaconBlockRoot: common.Hash{42},
	}

	require.ErrorContains(t, api.ValidateBuilderSubmissionV3(blockRequest), "inaccurate payment")
	blockRequest.Message.Value = uint256.NewInt(132912184722468)
	require.NoError(t, api.ValidateBuilderSubmissionV3(blockRequest))

	blockRequest.Message.GasLimit += 1
	blockRequest.ExecutionPayload.GasLimit += 1
	updatePayloadHashV3(t, blockRequest)

	require.ErrorContains(t, api.ValidateBuilderSubmissionV3(blockRequest), "incorrect gas limit set")

	blockRequest.Message.GasLimit -= 1
	blockRequest.ExecutionPayload.GasLimit -= 1
	updatePayloadHashV3(t, blockRequest)

	// TODO: test with contract calling blacklisted address
	// Test tx from blacklisted address
	api.accessVerifier = &AccessVerifier{
		blacklistedAddresses: map[common.Address]struct{}{
			testAddr: {},
		},
	}
	require.ErrorContains(t, api.ValidateBuilderSubmissionV3(blockRequest), "transaction from blacklisted address 0x71562b71999873DB5b286dF957af199Ec94617F7")

	// Test tx to blacklisted address
	api.accessVerifier = &AccessVerifier{
		blacklistedAddresses: map[common.Address]struct{}{
			{0x16}: {},
		},
	}
	require.ErrorContains(t, api.ValidateBuilderSubmissionV3(blockRequest), "transaction to blacklisted address 0x1600000000000000000000000000000000000000")

	api.accessVerifier = nil

	blockRequest.Message.GasUsed = 10
	require.ErrorContains(t, api.ValidateBuilderSubmissionV3(blockRequest), "incorrect GasUsed 10, expected 119996")
	blockRequest.Message.GasUsed = execData.GasUsed

	newTestKey, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f290")
	invalidTx, err := types.SignTx(types.NewTransaction(0, common.Address{}, new(big.Int).Mul(big.NewInt(2e18), big.NewInt(10)), 19000, big.NewInt(2*params.InitialBaseFee), nil), types.LatestSigner(ethservice.BlockChain().Config()), newTestKey)
	require.NoError(t, err)

	txData, err := invalidTx.MarshalBinary()
	require.NoError(t, err)
	execData.Transactions = append(execData.Transactions, txData)

	invalidPayload, err := ExecutableDataToExecutionPayloadV3(execData)
	require.NoError(t, err)
	invalidPayload.GasUsed = execData.GasUsed
	copy(invalidPayload.ReceiptsRoot[:], hexutil.MustDecode("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")[:32])
	blockRequest.ExecutionPayload = invalidPayload
	updatePayloadHashV3(t, blockRequest)
	require.ErrorContains(t, api.ValidateBuilderSubmissionV3(blockRequest), "could not apply tx 4", "insufficient funds for gas * price + value")
}

func updatePayloadHash(t *testing.T, blockRequest *BuilderBlockValidationRequest) {
	blockHash, err := utils.ComputeBlockHash(&api.VersionedExecutionPayload{Version: spec.DataVersionBellatrix, Bellatrix: blockRequest.ExecutionPayload}, nil)
	require.NoError(t, err)
	copy(blockRequest.Message.BlockHash[:], blockHash[:])
	copy(blockRequest.ExecutionPayload.BlockHash[:], blockHash[:])
}

func updatePayloadHashV2(t *testing.T, blockRequest *BuilderBlockValidationRequestV2) {
	blockHash, err := utils.ComputeBlockHash(&api.VersionedExecutionPayload{Version: spec.DataVersionCapella, Capella: blockRequest.ExecutionPayload}, nil)
	require.NoError(t, err)
	copy(blockRequest.Message.BlockHash[:], blockHash[:])
	copy(blockRequest.ExecutionPayload.BlockHash[:], blockHash[:])
}

func updatePayloadHashV3(t *testing.T, blockRequest *BuilderBlockValidationRequestV3) {
	root := phase0.Root(blockRequest.ParentBeaconBlockRoot)
	blockHash, err := utils.ComputeBlockHash(&api.VersionedExecutionPayload{Version: spec.DataVersionDeneb, Deneb: blockRequest.ExecutionPayload}, &root)
	require.NoError(t, err)
	copy(blockRequest.Message.BlockHash[:], blockHash[:])
	copy(blockRequest.ExecutionPayload.BlockHash[:], blockHash[:])
}

func generatePreMergeChain(n int) (*core.Genesis, []*types.Block) {
	db := rawdb.NewMemoryDatabase()
	config := params.AllEthashProtocolChanges
	genesis := &core.Genesis{
		Config:     config,
		Alloc:      types.GenesisAlloc{testAddr: {Balance: testBalance}, testValidatorAddr: {Balance: testBalance}, testBuilderAddr: {Balance: testBalance}},
		ExtraData:  []byte("test genesis"),
		Timestamp:  9000,
		BaseFee:    big.NewInt(params.InitialBaseFee),
		Difficulty: big.NewInt(0),
	}
	testNonce := uint64(0)
	generate := func(_ int, g *core.BlockGen) {
		g.OffsetTime(5)
		g.SetExtra([]byte("test"))
		tx, _ := types.SignTx(types.NewTransaction(testNonce, common.HexToAddress("0x9a9070028361F7AAbeB3f2F2Dc07F82C4a98A02a"), big.NewInt(1), params.TxGas, big.NewInt(params.InitialBaseFee*2), nil), types.LatestSigner(config), testKey)
		g.AddTx(tx)
		testNonce++
	}
	gblock := genesis.MustCommit(db, triedb.NewDatabase(db, triedb.HashDefaults))
	engine := ethash.NewFaker()
	blocks, _ := core.GenerateChain(config, gblock, engine, db, n, generate)
	totalDifficulty := big.NewInt(0)
	for _, b := range blocks {
		totalDifficulty.Add(totalDifficulty, b.Difficulty())
	}
	config.TerminalTotalDifficulty = totalDifficulty
	return genesis, blocks
}

func generateMergeChain(n int, merged bool) (*core.Genesis, []*types.Block) {
	config := *params.AllEthashProtocolChanges
	engine := consensus.Engine(beaconConsensus.New(ethash.NewFaker()))
	if merged {
		config.TerminalTotalDifficulty = common.Big0
		config.TerminalTotalDifficultyPassed = true
		engine = beaconConsensus.NewFaker()
	}
	genesis := &core.Genesis{
		Config: &config,
		Alloc: types.GenesisAlloc{
			testAddr:                         {Balance: testBalance},
			params.BeaconRootsStorageAddress: {Balance: common.Big0, Code: common.Hex2Bytes("3373fffffffffffffffffffffffffffffffffffffffe14604457602036146024575f5ffd5b620180005f350680545f35146037575f5ffd5b6201800001545f5260205ff35b6201800042064281555f359062018000015500")},
		},
		ExtraData:  []byte("test genesis"),
		Timestamp:  9000,
		BaseFee:    big.NewInt(params.InitialBaseFee),
		Difficulty: big.NewInt(0),
	}
	testNonce := uint64(0)
	generate := func(_ int, g *core.BlockGen) {
		g.OffsetTime(5)
		g.SetExtra([]byte("test"))
		tx, _ := types.SignTx(types.NewTransaction(testNonce, common.HexToAddress("0x9a9070028361F7AAbeB3f2F2Dc07F82C4a98A02a"), big.NewInt(1), params.TxGas, big.NewInt(params.InitialBaseFee*2), nil), types.LatestSigner(&config), testKey)
		g.AddTx(tx)
		testNonce++
	}
	_, blocks, _ := core.GenerateChainWithGenesis(genesis, engine, n, generate)

	if !merged {
		totalDifficulty := big.NewInt(0)
		for _, b := range blocks {
			totalDifficulty.Add(totalDifficulty, b.Difficulty())
		}
		config.TerminalTotalDifficulty = totalDifficulty
	}

	return genesis, blocks
}

// startEthService creates a full node instance for testing.
func startEthService(t *testing.T, genesis *core.Genesis, blocks []*types.Block) (*node.Node, *eth.Ethereum) {
	t.Helper()

	n, err := node.New(&node.Config{
		P2P: p2p.Config{
			ListenAddr:  "0.0.0.0:0",
			NoDiscovery: true,
			MaxPeers:    25,
		},
	})
	if err != nil {
		t.Fatal("can't create node:", err)
	}

	ethcfg := &ethconfig.Config{Genesis: genesis, SyncMode: downloader.FullSync, TrieTimeout: time.Minute, TrieDirtyCache: 256, TrieCleanCache: 256}
	ethservice, err := eth.New(n, ethcfg)
	if err != nil {
		t.Fatal("can't create eth service:", err)
	}
	if err := n.Start(); err != nil {
		t.Fatal("can't start node:", err)
	}
	if _, err := ethservice.BlockChain().InsertChain(blocks); err != nil {
		n.Close()
		t.Fatal("can't import test blocks:", err)
	}
	time.Sleep(500 * time.Millisecond) // give txpool enough time to consume head event

	ethservice.SetEtherbase(testAddr)
	ethservice.SetSynced()
	return n, ethservice
}

func assembleBlock(api *BlockValidationAPI, parentHash common.Hash, params *engine.PayloadAttributes) (*engine.ExecutableData, error) {
	args := &miner.BuildPayloadArgs{
		Parent:       parentHash,
		Timestamp:    params.Timestamp,
		FeeRecipient: params.SuggestedFeeRecipient,
		GasLimit:     params.GasLimit,
		Random:       params.Random,
		Withdrawals:  params.Withdrawals,
		BeaconRoot:   params.BeaconRoot,
	}

	payload, err := api.eth.Miner().BuildPayload(args)
	if err != nil {
		return nil, err
	}

	if payload := payload.ResolveFull(); payload != nil {
		return payload.ExecutionPayload, nil
	}

	return nil, errors.New("payload did not resolve")
}

func TestBlacklistLoad(t *testing.T) {
	file, err := os.CreateTemp(".", "blacklist")
	require.NoError(t, err)
	defer os.Remove(file.Name())

	av, err := NewAccessVerifierFromFile(file.Name())
	require.Error(t, err)
	require.Nil(t, av)

	ba := BlacklistedAddresses{common.Address{0x13}, common.Address{0x14}}
	bytes, err := json.MarshalIndent(ba, "", " ")
	require.NoError(t, err)
	err = os.WriteFile(file.Name(), bytes, 0o644)
	require.NoError(t, err)

	av, err = NewAccessVerifierFromFile(file.Name())
	require.NoError(t, err)
	require.NotNil(t, av)
	require.EqualValues(t, av.blacklistedAddresses, map[common.Address]struct{}{
		{0x13}: {},
		{0x14}: {},
	})

	require.NoError(t, av.verifyTraces(logger.NewAccessListTracer(nil, common.Address{}, common.Address{}, nil)))

	acl := types.AccessList{
		types.AccessTuple{
			Address: common.Address{0x14},
		},
	}
	tracer := logger.NewAccessListTracer(acl, common.Address{}, common.Address{}, nil)
	require.ErrorContains(t, av.verifyTraces(tracer), "blacklisted address 0x1400000000000000000000000000000000000000 in execution trace")

	acl = types.AccessList{
		types.AccessTuple{
			Address: common.Address{0x15},
		},
	}
	tracer = logger.NewAccessListTracer(acl, common.Address{}, common.Address{}, nil)
	require.NoError(t, av.verifyTraces(tracer))
}

func ExecutableDataToExecutionPayload(data *engine.ExecutableData) (*bellatrix.ExecutionPayload, error) {
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

func ExecutableDataToExecutionPayloadV2(data *engine.ExecutableData) (*capella.ExecutionPayload, error) {
	transactionData := make([]bellatrix.Transaction, len(data.Transactions))
	for i, tx := range data.Transactions {
		transactionData[i] = bellatrix.Transaction(tx)
	}

	withdrawalData := make([]*capella.Withdrawal, len(data.Withdrawals))
	for i, withdrawal := range data.Withdrawals {
		withdrawalData[i] = &capella.Withdrawal{
			Index:          capella.WithdrawalIndex(withdrawal.Index),
			ValidatorIndex: phase0.ValidatorIndex(withdrawal.Validator),
			Address:        bellatrix.ExecutionAddress(withdrawal.Address),
			Amount:         phase0.Gwei(withdrawal.Amount),
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

func ExecutableDataToExecutionPayloadV3(data *engine.ExecutableData) (*deneb.ExecutionPayload, error) {
	transactionData := make([]bellatrix.Transaction, len(data.Transactions))
	for i, tx := range data.Transactions {
		transactionData[i] = bellatrix.Transaction(tx)
	}

	withdrawalData := make([]*capella.Withdrawal, len(data.Withdrawals))
	for i, withdrawal := range data.Withdrawals {
		withdrawalData[i] = &capella.Withdrawal{
			Index:          capella.WithdrawalIndex(withdrawal.Index),
			ValidatorIndex: phase0.ValidatorIndex(withdrawal.Validator),
			Address:        bellatrix.ExecutionAddress(withdrawal.Address),
			Amount:         phase0.Gwei(withdrawal.Amount),
		}
	}

	return &deneb.ExecutionPayload{
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
		BaseFeePerGas: uint256.MustFromBig(data.BaseFeePerGas),
		BlockHash:     [32]byte(data.BlockHash),
		Transactions:  transactionData,
		Withdrawals:   withdrawalData,
		BlobGasUsed:   *data.BlobGasUsed,
		ExcessBlobGas: *data.ExcessBlobGas,
	}, nil
}

func WithdrawalToBlockRequestWithdrawal(withdrawals types.Withdrawals) []*capella.Withdrawal {
	withdrawalsData := make([]*capella.Withdrawal, len(withdrawals))
	for i, withdrawal := range withdrawals {
		withdrawalsData[i] = &capella.Withdrawal{
			Index:          capella.WithdrawalIndex(i),
			ValidatorIndex: phase0.ValidatorIndex(withdrawal.Validator),
			Address:        bellatrix.ExecutionAddress(withdrawal.Address),
			Amount:         phase0.Gwei(withdrawal.Amount),
		}
	}
	return withdrawalsData
}

type buildBlockArgs struct {
	parentHash    common.Hash
	parentRoot    common.Hash
	feeRecipient  common.Address
	txs           types.Transactions
	random        common.Hash
	number        uint64
	gasLimit      uint64
	timestamp     uint64
	extraData     []byte
	baseFeePerGas *big.Int
	withdrawals   types.Withdrawals
}

func buildBlock(args buildBlockArgs, chain *core.BlockChain) (*engine.ExecutableData, error) {
	header := &types.Header{
		ParentHash: args.parentHash,
		Coinbase:   args.feeRecipient,
		Number:     big.NewInt(int64(args.number)),
		GasLimit:   args.gasLimit,
		Time:       args.timestamp,
		Extra:      args.extraData,
		BaseFee:    args.baseFeePerGas,
		MixDigest:  args.random,
	}

	err := chain.Engine().Prepare(chain, header)
	if err != nil {
		return nil, err
	}

	statedb, err := chain.StateAt(args.parentRoot)
	if err != nil {
		return nil, err
	}

	receipts := make([]*types.Receipt, 0, len(args.txs))
	gasPool := core.GasPool(header.GasLimit)
	vmConfig := vm.Config{}
	for i, tx := range args.txs {
		statedb.SetTxContext(tx.Hash(), i)
		receipt, err := core.ApplyTransaction(chain.Config(), chain, &args.feeRecipient, &gasPool, statedb, header, tx, &header.GasUsed, vmConfig, nil)
		if err != nil {
			return nil, err
		}
		receipts = append(receipts, receipt)
	}

	block, err := chain.Engine().FinalizeAndAssemble(chain, header, statedb, args.txs, nil, receipts, args.withdrawals)
	if err != nil {
		return nil, err
	}

	execData := engine.BlockToExecutableData(block, common.Big0, nil)

	return execData.ExecutionPayload, nil
}

func executableDataToBlockValidationRequest(execData *engine.ExecutableData, proposer common.Address, value *big.Int, withdrawalsRoot common.Hash) (*BuilderBlockValidationRequestV2, error) {
	payload, err := ExecutableDataToExecutionPayloadV2(execData)
	if err != nil {
		return nil, err
	}

	proposerAddr := bellatrix.ExecutionAddress{}
	copy(proposerAddr[:], proposer.Bytes())

	value256, overflow := uint256.FromBig(value)
	if overflow {
		return nil, errors.New("could not convert value to uint256")
	}
	blockRequest := &BuilderBlockValidationRequestV2{
		SubmitBlockRequest: builderApiCapella.SubmitBlockRequest{
			Signature: phase0.BLSSignature{},
			Message: &builderApiV1.BidTrace{
				ParentHash:           phase0.Hash32(execData.ParentHash),
				BlockHash:            phase0.Hash32(execData.BlockHash),
				ProposerFeeRecipient: proposerAddr,
				GasLimit:             execData.GasLimit,
				GasUsed:              execData.GasUsed,
				Value:                value256,
			},
			ExecutionPayload: payload,
		},
		RegisteredGasLimit: execData.GasLimit,
	}
	return blockRequest, nil
}

// This tests payment when the proposer fee recipient is the same as the coinbase
func TestValidateBuilderSubmissionV2_CoinbasePaymentDefault(t *testing.T) {
	genesis, preMergeBlocks := generatePreMergeChain(20)
	lastBlock := preMergeBlocks[len(preMergeBlocks)-1]
	time := lastBlock.Time() + 5
	genesis.Config.ShanghaiTime = &time
	n, ethservice := startEthService(t, genesis, preMergeBlocks)
	ethservice.Merger().ReachTTD()
	defer n.Close()

	api := NewBlockValidationAPI(ethservice, nil, true, true)

	baseFee := eip1559.CalcBaseFee(ethservice.BlockChain().Config(), lastBlock.Header())
	txs := make(types.Transactions, 0)

	statedb, _ := ethservice.BlockChain().StateAt(lastBlock.Root())
	nonce := statedb.GetNonce(testAddr)
	signer := types.LatestSigner(ethservice.BlockChain().Config())

	expectedProfit := uint64(0)

	tx1, _ := types.SignTx(types.NewTransaction(nonce, common.Address{0x16}, big.NewInt(10), 21000, big.NewInt(2*baseFee.Int64()), nil), signer, testKey)
	txs = append(txs, tx1)
	expectedProfit += 21000 * baseFee.Uint64()

	// this tx will use 56996 gas
	tx2, _ := types.SignTx(types.NewContractCreation(nonce+1, new(big.Int), 1000000, big.NewInt(2*baseFee.Int64()), logCode), signer, testKey)
	txs = append(txs, tx2)
	expectedProfit += 56996 * baseFee.Uint64()

	tx3, _ := types.SignTx(types.NewTransaction(nonce+2, testAddr, big.NewInt(10), 21000, baseFee, nil), signer, testKey)
	txs = append(txs, tx3)

	// this transaction sends 7 wei to the proposer fee recipient, this should count as a profit
	tx4, _ := types.SignTx(types.NewTransaction(nonce+3, testValidatorAddr, big.NewInt(7), 21000, baseFee, nil), signer, testKey)
	txs = append(txs, tx4)
	expectedProfit += 7

	// transactions from the proposer fee recipient

	// this transaction sends 3 wei from the proposer fee recipient to the proposer fee recipient and pays tip of baseFee
	// this should not count as a profit (because balance does not increase)
	// Base fee is burned from the balance so it should decrease decreasing the profit.
	tx5, _ := types.SignTx(types.NewTransaction(0, testValidatorAddr, big.NewInt(3), 21000, big.NewInt(2*baseFee.Int64()), nil), signer, testValidatorKey)
	txs = append(txs, tx5)
	expectedProfit -= 21000 * baseFee.Uint64()

	// this tx sends 11 wei from the proposer fee recipient to some other address and burns 21000*baseFee
	// this should count as negative profit
	tx6, _ := types.SignTx(types.NewTransaction(1, testAddr, big.NewInt(11), 21000, baseFee, nil), signer, testValidatorKey)
	txs = append(txs, tx6)
	expectedProfit -= 11 + 21000*baseFee.Uint64()

	withdrawals := []*types.Withdrawal{
		{
			Index:     0,
			Validator: 1,
			Amount:    100,
			Address:   testAddr,
		},
		{
			Index:     1,
			Validator: 1,
			Amount:    100,
			Address:   testAddr,
		},
	}
	withdrawalsRoot := types.DeriveSha(types.Withdrawals(withdrawals), trie.NewStackTrie(nil))

	buildBlockArgs := buildBlockArgs{
		parentHash:    lastBlock.Hash(),
		parentRoot:    lastBlock.Root(),
		feeRecipient:  testValidatorAddr,
		txs:           txs,
		random:        common.Hash{},
		number:        lastBlock.NumberU64() + 1,
		gasLimit:      lastBlock.GasLimit(),
		timestamp:     lastBlock.Time() + 5,
		extraData:     nil,
		baseFeePerGas: baseFee,
		withdrawals:   withdrawals,
	}

	execData, err := buildBlock(buildBlockArgs, ethservice.BlockChain())
	require.NoError(t, err)

	value := big.NewInt(int64(expectedProfit))

	req, err := executableDataToBlockValidationRequest(execData, testValidatorAddr, value, withdrawalsRoot)
	require.NoError(t, err)
	require.NoError(t, api.ValidateBuilderSubmissionV2(req))

	// try to claim less profit than expected, should work
	value.SetUint64(expectedProfit - 1)

	req, err = executableDataToBlockValidationRequest(execData, testValidatorAddr, value, withdrawalsRoot)
	require.NoError(t, err)
	require.NoError(t, api.ValidateBuilderSubmissionV2(req))

	// try to claim more profit than expected, should fail
	value.SetUint64(expectedProfit + 1)

	req, err = executableDataToBlockValidationRequest(execData, testValidatorAddr, value, withdrawalsRoot)
	require.NoError(t, err)
	require.ErrorContains(t, api.ValidateBuilderSubmissionV2(req), "payment")
}

func TestValidateBuilderSubmissionV2_Blocklist(t *testing.T) {
	genesis, preMergeBlocks := generatePreMergeChain(20)
	lastBlock := preMergeBlocks[len(preMergeBlocks)-1]
	time := lastBlock.Time() + 5
	genesis.Config.ShanghaiTime = &time
	n, ethservice := startEthService(t, genesis, preMergeBlocks)
	ethservice.Merger().ReachTTD()
	defer n.Close()

	accessVerifier := &AccessVerifier{
		blacklistedAddresses: map[common.Address]struct{}{
			testAddr: {},
		},
	}

	apiWithBlock := NewBlockValidationAPI(ethservice, accessVerifier, true, true)
	apiNoBlock := NewBlockValidationAPI(ethservice, nil, true, true)

	baseFee := eip1559.CalcBaseFee(ethservice.BlockChain().Config(), lastBlock.Header())
	blockedTxs := make(types.Transactions, 0)

	statedb, _ := ethservice.BlockChain().StateAt(lastBlock.Root())

	signer := types.LatestSigner(ethservice.BlockChain().Config())

	nonce := statedb.GetNonce(testAddr)
	tx, _ := types.SignTx(types.NewTransaction(nonce, common.Address{0x16}, big.NewInt(10), 21000, baseFee, nil), signer, testKey)
	blockedTxs = append(blockedTxs, tx)

	nonce = statedb.GetNonce(testBuilderAddr)
	tx, _ = types.SignTx(types.NewTransaction(nonce, testAddr, big.NewInt(10), 21000, baseFee, nil), signer, testBuilderKey)
	blockedTxs = append(blockedTxs, tx)

	withdrawalsRoot := types.DeriveSha(types.Withdrawals(nil), trie.NewStackTrie(nil))

	for i, tx := range blockedTxs {
		t.Run(fmt.Sprintf("tx %d", i), func(t *testing.T) {
			buildBlockArgs := buildBlockArgs{
				parentHash:    lastBlock.Hash(),
				parentRoot:    lastBlock.Root(),
				feeRecipient:  testValidatorAddr,
				txs:           types.Transactions{tx},
				random:        common.Hash{},
				number:        lastBlock.NumberU64() + 1,
				gasLimit:      lastBlock.GasLimit(),
				timestamp:     lastBlock.Time() + 5,
				extraData:     nil,
				baseFeePerGas: baseFee,
				withdrawals:   nil,
			}

			execData, err := buildBlock(buildBlockArgs, ethservice.BlockChain())
			require.NoError(t, err)

			req, err := executableDataToBlockValidationRequest(execData, testValidatorAddr, common.Big0, withdrawalsRoot)
			require.NoError(t, err)

			require.NoError(t, apiNoBlock.ValidateBuilderSubmissionV2(req))
			require.ErrorContains(t, apiWithBlock.ValidateBuilderSubmissionV2(req), "blacklisted")
		})
	}
}

// This tests payment when the proposer fee recipient receives CL withdrawal.
func TestValidateBuilderSubmissionV2_ExcludeWithdrawals(t *testing.T) {
	genesis, preMergeBlocks := generatePreMergeChain(20)
	lastBlock := preMergeBlocks[len(preMergeBlocks)-1]
	time := lastBlock.Time() + 5
	genesis.Config.ShanghaiTime = &time
	n, ethservice := startEthService(t, genesis, preMergeBlocks)
	ethservice.Merger().ReachTTD()
	defer n.Close()

	api := NewBlockValidationAPI(ethservice, nil, true, true)

	baseFee := eip1559.CalcBaseFee(ethservice.BlockChain().Config(), lastBlock.Header())
	txs := make(types.Transactions, 0)

	statedb, _ := ethservice.BlockChain().StateAt(lastBlock.Root())
	nonce := statedb.GetNonce(testAddr)
	signer := types.LatestSigner(ethservice.BlockChain().Config())

	expectedProfit := uint64(0)

	tx1, _ := types.SignTx(types.NewTransaction(nonce, common.Address{0x16}, big.NewInt(10), 21000, big.NewInt(2*baseFee.Int64()), nil), signer, testKey)
	txs = append(txs, tx1)
	expectedProfit += 21000 * baseFee.Uint64()

	// this tx will use 56996 gas
	tx2, _ := types.SignTx(types.NewContractCreation(nonce+1, new(big.Int), 1000000, big.NewInt(2*baseFee.Int64()), logCode), signer, testKey)
	txs = append(txs, tx2)
	expectedProfit += 56996 * baseFee.Uint64()

	tx3, _ := types.SignTx(types.NewTransaction(nonce+2, testAddr, big.NewInt(10), 21000, baseFee, nil), signer, testKey)
	txs = append(txs, tx3)

	// this transaction sends 7 wei to the proposer fee recipient, this should count as a profit
	tx4, _ := types.SignTx(types.NewTransaction(nonce+3, testValidatorAddr, big.NewInt(7), 21000, baseFee, nil), signer, testKey)
	txs = append(txs, tx4)
	expectedProfit += 7

	withdrawals := []*types.Withdrawal{
		{
			Index:     0,
			Validator: 1,
			Amount:    100,
			Address:   testAddr,
		},
		{
			Index:     1,
			Validator: 1,
			Amount:    17,
			Address:   testValidatorAddr,
		},
		{
			Index:     1,
			Validator: 1,
			Amount:    21,
			Address:   testValidatorAddr,
		},
	}
	withdrawalsRoot := types.DeriveSha(types.Withdrawals(withdrawals), trie.NewStackTrie(nil))

	buildBlockArgs := buildBlockArgs{
		parentHash:    lastBlock.Hash(),
		parentRoot:    lastBlock.Root(),
		feeRecipient:  testValidatorAddr,
		txs:           txs,
		random:        common.Hash{},
		number:        lastBlock.NumberU64() + 1,
		gasLimit:      lastBlock.GasLimit(),
		timestamp:     lastBlock.Time() + 5,
		extraData:     nil,
		baseFeePerGas: baseFee,
		withdrawals:   withdrawals,
	}

	execData, err := buildBlock(buildBlockArgs, ethservice.BlockChain())
	require.NoError(t, err)

	value := big.NewInt(int64(expectedProfit))

	req, err := executableDataToBlockValidationRequest(execData, testValidatorAddr, value, withdrawalsRoot)
	require.NoError(t, err)
	require.NoError(t, api.ValidateBuilderSubmissionV2(req))

	// try to claim less profit than expected, should work
	value.SetUint64(expectedProfit - 1)

	req, err = executableDataToBlockValidationRequest(execData, testValidatorAddr, value, withdrawalsRoot)
	require.NoError(t, err)
	require.NoError(t, api.ValidateBuilderSubmissionV2(req))

	// try to claim more profit than expected, should fail
	value.SetUint64(expectedProfit + 1)

	req, err = executableDataToBlockValidationRequest(execData, testValidatorAddr, value, withdrawalsRoot)
	require.NoError(t, err)
	require.ErrorContains(t, api.ValidateBuilderSubmissionV2(req), "payment")
}
