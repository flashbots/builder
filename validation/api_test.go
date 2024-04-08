package validation

import (
	"bytes"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	builderApiDeneb "github.com/attestantio/go-builder-client/api/deneb"
	builderApiV1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	beaconConsensus "github.com/ethereum/go-ethereum/consensus/beacon"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth"
	blockvalidation "github.com/ethereum/go-ethereum/eth/block-validation"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/miner"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

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
)

func generateMergeChain(n int) (*core.Genesis, []*types.Block) {
	config := *params.AllEthashProtocolChanges

	config.TerminalTotalDifficulty = common.Big0
	config.TerminalTotalDifficultyPassed = true
	engine := beaconConsensus.NewFaker()

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

func assembleBlock(eth *eth.Ethereum, parentHash common.Hash, params *engine.PayloadAttributes) (*engine.ExecutableData, error) {
	args := &miner.BuildPayloadArgs{
		Parent:       parentHash,
		Timestamp:    params.Timestamp,
		FeeRecipient: params.SuggestedFeeRecipient,
		GasLimit:     params.GasLimit,
		Random:       params.Random,
		Withdrawals:  params.Withdrawals,
		BeaconRoot:   params.BeaconRoot,
	}

	payload, err := eth.Miner().BuildPayload(args)
	if err != nil {
		return nil, err
	}

	if payload := payload.ResolveFull(); payload != nil {
		return payload.ExecutionPayload, nil
	}

	return nil, errors.New("payload did not resolve")
}

type testBackend struct {
	api *BlockValidationApi
}

// newTestBackend creates a new backend, initializes mock relays, registers them and return the instance
func newTestBackend(t *testing.T, ethservice *eth.Ethereum) *testBackend {
	t.Helper()

	api := &BlockValidationApi{
		validationApi: blockvalidation.NewBlockValidationAPI(ethservice, nil, true, true),
	}

	backend := testBackend{api}
	return &backend
}

func (be *testBackend) request(t *testing.T, method, path string, payload []byte) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	var err error

	if payload == nil {
		req, err = http.NewRequest(method, path, bytes.NewReader(nil))
	} else {
		req, err = http.NewRequest(method, path, bytes.NewReader(payload))
		req.Header.Add("Content-Type", "application/octet-stream")
	}

	require.NoError(t, err)
	rr := httptest.NewRecorder()
	be.api.getRouter().ServeHTTP(rr, req)
	return rr
}

func TestBlockValidation(t *testing.T) {
	genesis, blocks := generateMergeChain(10)

	// Set cancun time to last block + 5 seconds
	time := blocks[len(blocks)-1].Time() + 5
	genesis.Config.ShanghaiTime = &time
	genesis.Config.CancunTime = &time
	os.Setenv("BUILDER_TX_SIGNING_KEY", testBuilderKeyHex)

	n, ethservice := startEthService(t, genesis, blocks)
	defer n.Close()

	backend := newTestBackend(t, ethservice)

	parent := ethservice.BlockChain().CurrentHeader()
	statedb, err := ethservice.BlockChain().StateAt(parent.Root)
	require.NoError(t, err)
	nonce := statedb.GetNonce(testAddr)
	ethservice.APIBackend.Miner().SetEtherbase(testBuilderAddr)

	tx1, err := types.SignTx(types.NewTransaction(nonce, common.Address{0x16}, big.NewInt(10), 21000, big.NewInt(2*params.InitialBaseFee), nil), types.LatestSigner(ethservice.BlockChain().Config()), testKey)
	require.NoError(t, err)
	ethservice.TxPool().Add([]*types.Transaction{tx1}, true, true, false)

	cc, err := types.SignTx(types.NewContractCreation(nonce+1, new(big.Int), 1000000, big.NewInt(2*params.InitialBaseFee), nil), types.LatestSigner(ethservice.BlockChain().Config()), testKey)
	require.NoError(t, err)
	ethservice.TxPool().Add([]*types.Transaction{cc}, true, true, false)

	baseFee := eip1559.CalcBaseFee(params.AllEthashProtocolChanges, parent)
	tx2, err := types.SignTx(types.NewTransaction(nonce+2, testAddr, big.NewInt(10), 21000, baseFee, nil), types.LatestSigner(ethservice.BlockChain().Config()), testKey)
	require.NoError(t, err)
	ethservice.TxPool().Add([]*types.Transaction{tx2}, true, true, false)

	execData, err := assembleBlock(ethservice, parent.Hash(), &engine.PayloadAttributes{
		Timestamp:             parent.Time + 12,
		SuggestedFeeRecipient: testValidatorAddr,
		Withdrawals:           []*types.Withdrawal{},
		BeaconRoot:            &common.Hash{42},
	})
	require.NoError(t, err)
	payload, err := ExecutableDataToExecutionPayloadV3(execData)
	require.NoError(t, err)
	blockRequest := &BuilderBlockValidationRequestV3{
		SubmitBlockRequest: builderApiDeneb.SubmitBlockRequest{
			Signature: phase0.BLSSignature{},
			Message: &builderApiV1.BidTrace{
				ParentHash:           phase0.Hash32(execData.ParentHash),
				BlockHash:            phase0.Hash32(execData.BlockHash),
				ProposerFeeRecipient: bellatrix.ExecutionAddress(testValidatorAddr),
				GasLimit:             execData.GasLimit,
				GasUsed:              execData.GasUsed,
				// This value is actual profit + 1, validation should fail
				Value: uint256.NewInt(125851807635001),
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

	payloadBytes, err := blockRequest.MarshalSSZ()
	require.NoError(t, err)
	rr := backend.request(t, http.MethodPost, "/validate/block_submission", payloadBytes)
	require.Equal(t, `{"code":400,"message":"inaccurate payment 125851807635000, expected 125851807635001"}`+"\n", rr.Body.String())
	require.Equal(t, http.StatusBadRequest, rr.Code)

	blockRequest.Message.Value = uint256.NewInt(125851807635000)
	payloadBytes, err = blockRequest.MarshalSSZ()
	require.NoError(t, err)
	rr = backend.request(t, http.MethodPost, "/validate/block_submission", payloadBytes)
	require.Equal(t, http.StatusOK, rr.Code)
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
