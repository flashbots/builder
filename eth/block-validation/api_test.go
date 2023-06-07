package blockvalidation

import (
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"testing"
	"time"

	bellatrixapi "github.com/attestantio/go-builder-client/api/bellatrix"
	capellaapi "github.com/attestantio/go-builder-client/api/capella"
	apiv1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
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
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"

	boostTypes "github.com/flashbots/go-boost-utils/types"
)

/* Based on catalyst API tests */

var (
	// testKey is a private key to use for funding a tester account.
	testKey, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")

	// testAddr is the Ethereum address of the tester account.
	testAddr = crypto.PubkeyToAddress(testKey.PublicKey)

	testValidatorKey, _ = crypto.HexToECDSA("28c3cd61b687fdd03488e167a5d84f50269df2a4c29a2cfb1390903aa775c5d0")
	testValidatorAddr   = crypto.PubkeyToAddress(testValidatorKey.PublicKey)

	testBalance = big.NewInt(2e18)
)

func TestValidateBuilderSubmissionV1(t *testing.T) {
	genesis, preMergeBlocks := generatePreMergeChain(20)
	os.Setenv("BUILDER_TX_SIGNING_KEY", "0x28c3cd61b687fdd03488e167a5d84f50269df2a4c29a2cfb1390903aa775c5d0")
	n, ethservice := startEthService(t, genesis, preMergeBlocks)
	ethservice.Merger().ReachTTD()
	defer n.Close()

	api := NewBlockValidationAPI(ethservice, nil)
	parent := preMergeBlocks[len(preMergeBlocks)-1]

	api.eth.APIBackend.Miner().SetEtherbase(testValidatorAddr)

	// This EVM code generates a log when the contract is created.
	logCode := common.Hex2Bytes("60606040525b7f24ec1d3ff24c2f6ff210738839dbc339cd45a5294d85c79361016243157aae7b60405180905060405180910390a15b600a8060416000396000f360606040526008565b00")

	statedb, _ := ethservice.BlockChain().StateAt(parent.Root())
	nonce := statedb.GetNonce(testAddr)

	tx1, _ := types.SignTx(types.NewTransaction(nonce, common.Address{0x16}, big.NewInt(10), 21000, big.NewInt(2*params.InitialBaseFee), nil), types.LatestSigner(ethservice.BlockChain().Config()), testKey)
	ethservice.TxPool().AddLocal(tx1)

	cc, _ := types.SignTx(types.NewContractCreation(nonce+1, new(big.Int), 1000000, big.NewInt(2*params.InitialBaseFee), logCode), types.LatestSigner(ethservice.BlockChain().Config()), testKey)
	ethservice.TxPool().AddLocal(cc)

	baseFee := misc.CalcBaseFee(params.AllEthashProtocolChanges, preMergeBlocks[len(preMergeBlocks)-1].Header())
	tx2, _ := types.SignTx(types.NewTransaction(nonce+2, testAddr, big.NewInt(10), 21000, baseFee, nil), types.LatestSigner(ethservice.BlockChain().Config()), testKey)
	ethservice.TxPool().AddLocal(tx2)

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
		SubmitBlockRequest: bellatrixapi.SubmitBlockRequest{
			Signature: phase0.BLSSignature{},
			Message: &apiv1.BidTrace{
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
	os.Setenv("BUILDER_TX_SIGNING_KEY", "0x28c3cd61b687fdd03488e167a5d84f50269df2a4c29a2cfb1390903aa775c5d0")
	time := preMergeBlocks[len(preMergeBlocks)-1].Time() + 5
	genesis.Config.ShanghaiTime = &time
	n, ethservice := startEthService(t, genesis, preMergeBlocks)
	ethservice.Merger().ReachTTD()
	defer n.Close()

	api := NewBlockValidationAPI(ethservice, nil)
	parent := preMergeBlocks[len(preMergeBlocks)-1]

	api.eth.APIBackend.Miner().SetEtherbase(testValidatorAddr)

	// This EVM code generates a log when the contract is created.
	logCode := common.Hex2Bytes("60606040525b7f24ec1d3ff24c2f6ff210738839dbc339cd45a5294d85c79361016243157aae7b60405180905060405180910390a15b600a8060416000396000f360606040526008565b00")

	statedb, _ := ethservice.BlockChain().StateAt(parent.Root())
	nonce := statedb.GetNonce(testAddr)

	tx1, _ := types.SignTx(types.NewTransaction(nonce, common.Address{0x16}, big.NewInt(10), 21000, big.NewInt(2*params.InitialBaseFee), nil), types.LatestSigner(ethservice.BlockChain().Config()), testKey)
	ethservice.TxPool().AddLocal(tx1)

	cc, _ := types.SignTx(types.NewContractCreation(nonce+1, new(big.Int), 1000000, big.NewInt(2*params.InitialBaseFee), logCode), types.LatestSigner(ethservice.BlockChain().Config()), testKey)
	ethservice.TxPool().AddLocal(cc)

	baseFee := misc.CalcBaseFee(params.AllEthashProtocolChanges, preMergeBlocks[len(preMergeBlocks)-1].Header())
	tx2, _ := types.SignTx(types.NewTransaction(nonce+2, testAddr, big.NewInt(10), 21000, baseFee, nil), types.LatestSigner(ethservice.BlockChain().Config()), testKey)
	ethservice.TxPool().AddLocal(tx2)

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
		SubmitBlockRequest: capellaapi.SubmitBlockRequest{
			Signature: phase0.BLSSignature{},
			Message: &apiv1.BidTrace{
				ParentHash:           phase0.Hash32(execData.ParentHash),
				BlockHash:            phase0.Hash32(execData.BlockHash),
				ProposerFeeRecipient: proposerAddr,
				GasLimit:             execData.GasLimit,
				GasUsed:              execData.GasUsed,
				Value:                uint256.NewInt(0),
			},
			ExecutionPayload: payload,
		},
		RegisteredGasLimit: execData.GasLimit,
		WithdrawalsRoot:    withdrawalsRoot,
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

func updatePayloadHash(t *testing.T, blockRequest *BuilderBlockValidationRequest) {
	updatedBlock, err := engine.ExecutionPayloadToBlock(blockRequest.ExecutionPayload)
	require.NoError(t, err)
	copy(blockRequest.Message.BlockHash[:], updatedBlock.Hash().Bytes()[:32])
}

func updatePayloadHashV2(t *testing.T, blockRequest *BuilderBlockValidationRequestV2) {
	updatedBlock, err := engine.ExecutionPayloadV2ToBlock(blockRequest.ExecutionPayload)
	require.NoError(t, err)
	copy(blockRequest.Message.BlockHash[:], updatedBlock.Hash().Bytes()[:32])
}

func generatePreMergeChain(n int) (*core.Genesis, []*types.Block) {
	db := rawdb.NewMemoryDatabase()
	config := params.AllEthashProtocolChanges
	genesis := &core.Genesis{
		Config:     config,
		Alloc:      core.GenesisAlloc{testAddr: {Balance: testBalance}},
		ExtraData:  []byte("test genesis"),
		Timestamp:  9000,
		BaseFee:    big.NewInt(params.InitialBaseFee),
		Difficulty: big.NewInt(0),
	}
	testNonce := uint64(0)
	generate := func(i int, g *core.BlockGen) {
		g.OffsetTime(5)
		g.SetExtra([]byte("test"))
		tx, _ := types.SignTx(types.NewTransaction(testNonce, common.HexToAddress("0x9a9070028361F7AAbeB3f2F2Dc07F82C4a98A02a"), big.NewInt(1), params.TxGas, big.NewInt(params.InitialBaseFee*2), nil), types.LatestSigner(config), testKey)
		g.AddTx(tx)
		testNonce++
	}
	gblock := genesis.MustCommit(db)
	engine := ethash.NewFaker()
	blocks, _ := core.GenerateChain(config, gblock, engine, db, n, generate)
	totalDifficulty := big.NewInt(0)
	for _, b := range blocks {
		totalDifficulty.Add(totalDifficulty, b.Difficulty())
	}
	config.TerminalTotalDifficulty = totalDifficulty
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
		}})
	if err != nil {
		t.Fatal("can't create node:", err)
	}

	ethcfg := &ethconfig.Config{Genesis: genesis, Ethash: ethash.Config{PowMode: ethash.ModeFake}, SyncMode: downloader.SnapSync, TrieTimeout: time.Minute, TrieDirtyCache: 256, TrieCleanCache: 256}
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
	err = os.WriteFile(file.Name(), bytes, 0644)
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
