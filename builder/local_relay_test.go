package builder

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/flashbotsextra"
	"github.com/ethereum/go-ethereum/log"
	"github.com/flashbots/go-boost-utils/bls"
	boostTypes "github.com/flashbots/go-boost-utils/types"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

func newTestBackend(t *testing.T, forkchoiceData *engine.ExecutableData, block *types.Block, blockValue *big.Int) (*Builder, *LocalRelay, *ValidatorPrivateData) {
	validator := NewRandomValidator()
	sk, _ := bls.GenerateRandomSecretKey()
	bDomain := boostTypes.ComputeDomain(boostTypes.DomainTypeAppBuilder, [4]byte{0x02, 0x0, 0x0, 0x0}, boostTypes.Hash{})
	genesisValidatorsRoot := boostTypes.Hash(common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000"))
	cDomain := boostTypes.ComputeDomain(boostTypes.DomainTypeBeaconProposer, [4]byte{0x02, 0x0, 0x0, 0x0}, genesisValidatorsRoot)
	beaconClient := &testBeaconClient{validator: validator}
	localRelay := NewLocalRelay(sk, beaconClient, bDomain, cDomain, ForkData{}, true)
	ethService := &testEthereumService{synced: true, testExecutableData: forkchoiceData, testBlock: block, testBlockValue: blockValue}
	builderArgs := BuilderArgs{
		sk:                          sk,
		ds:                          flashbotsextra.NilDbService{},
		relay:                       localRelay,
		builderSigningDomain:        bDomain,
		eth:                         ethService,
		dryRun:                      false,
		ignoreLatePayloadAttributes: false,
		validator:                   nil,
		beaconClient:                beaconClient,
		limiter:                     nil,
	}
	backend := NewBuilder(builderArgs)
	// service := NewService("127.0.0.1:31545", backend)

	backend.limiter = rate.NewLimiter(rate.Inf, 0)

	return backend, localRelay, validator
}

func testRequest(t *testing.T, localRelay *LocalRelay, method, path string, payload any) *httptest.ResponseRecorder {
	var req *http.Request
	var err error

	if payload == nil {
		req, err = http.NewRequest(method, path, nil)
	} else {
		payloadBytes, err2 := json.Marshal(payload)
		require.NoError(t, err2)
		req, err = http.NewRequest(method, path, bytes.NewReader(payloadBytes))
	}

	require.NoError(t, err)
	rr := httptest.NewRecorder()
	getRouter(localRelay).ServeHTTP(rr, req)
	return rr
}

func TestValidatorRegistration(t *testing.T) {
	_, relay, _ := newTestBackend(t, nil, nil, nil)

	v := NewRandomValidator()
	payload, err := prepareRegistrationMessage(t, relay.builderSigningDomain, v)
	require.NoError(t, err)

	rr := testRequest(t, relay, "POST", "/eth/v1/builder/validators", payload)
	require.Equal(t, http.StatusOK, rr.Code)
	require.Contains(t, relay.validators, PubkeyHex(v.Pk.String()))
	require.Equal(t, FullValidatorData{ValidatorData: ValidatorData{Pubkey: PubkeyHex(v.Pk.String()), FeeRecipient: payload[0].Message.FeeRecipient, GasLimit: payload[0].Message.GasLimit}, Timestamp: payload[0].Message.Timestamp}, relay.validators[PubkeyHex(v.Pk.String())])

	rr = testRequest(t, relay, "POST", "/eth/v1/builder/validators", payload)
	require.Equal(t, http.StatusOK, rr.Code)

	payload[0].Message.Timestamp += 1
	// Invalid signature
	payload[0].Signature[len(payload[0].Signature)-1] = 0x00
	rr = testRequest(t, relay, "POST", "/eth/v1/builder/validators", payload)
	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Equal(t, `{"code":400,"message":"invalid signature"}`+"\n", rr.Body.String())

	// TODO: cover all errors
}

func prepareRegistrationMessage(t *testing.T, domain boostTypes.Domain, v *ValidatorPrivateData) ([]boostTypes.SignedValidatorRegistration, error) {
	var pubkey boostTypes.PublicKey
	pubkey.FromSlice(v.Pk)
	require.Equal(t, []byte(v.Pk), pubkey[:])

	msg := boostTypes.RegisterValidatorRequestMessage{
		FeeRecipient: boostTypes.Address{0x42},
		GasLimit:     15_000_000,
		Timestamp:    uint64(time.Now().Unix()),
		Pubkey:       pubkey,
	}

	signature, err := v.Sign(&msg, domain)
	require.NoError(t, err)

	return []boostTypes.SignedValidatorRegistration{{
		Message:   &msg,
		Signature: signature,
	}}, nil
}

func registerValidator(t *testing.T, v *ValidatorPrivateData, relay *LocalRelay) {
	payload, err := prepareRegistrationMessage(t, relay.builderSigningDomain, v)
	require.NoError(t, err)

	log.Info("Registering", "payload", payload[0].Message)
	rr := testRequest(t, relay, "POST", "/eth/v1/builder/validators", payload)
	require.Equal(t, http.StatusOK, rr.Code)
	require.Contains(t, relay.validators, PubkeyHex(v.Pk.String()))
	require.Equal(t, FullValidatorData{ValidatorData: ValidatorData{Pubkey: PubkeyHex(v.Pk.String()), FeeRecipient: payload[0].Message.FeeRecipient, GasLimit: payload[0].Message.GasLimit}, Timestamp: payload[0].Message.Timestamp}, relay.validators[PubkeyHex(v.Pk.String())])
}

func TestGetHeader(t *testing.T) {
	forkchoiceData := &engine.ExecutableData{
		ParentHash:    common.HexToHash("0xafafafa"),
		FeeRecipient:  common.Address{0x01},
		LogsBloom:     types.Bloom{0x00, 0x05, 0x10}.Bytes(),
		BlockHash:     common.HexToHash("0x24e6998e4d2b4fd85f7f0d27ac4b87aaf0ec18e156e4b6e194ab5dadee0cd004"),
		BaseFeePerGas: big.NewInt(12),
		ExtraData:     []byte{},
	}

	forkchoiceBlock, err := engine.ExecutableDataToBlock(*forkchoiceData)
	require.NoError(t, err)
	forkchoiceBlockProfit := big.NewInt(10)

	backend, relay, validator := newTestBackend(t, forkchoiceData, forkchoiceBlock, forkchoiceBlockProfit)

	path := fmt.Sprintf("/eth/v1/builder/header/%d/%s/%s", 0, forkchoiceData.ParentHash.Hex(), validator.Pk.String())
	rr := testRequest(t, relay, "GET", path, nil)
	require.Equal(t, `{"code":400,"message":"unknown validator"}`+"\n", rr.Body.String())

	registerValidator(t, validator, relay)

	rr = testRequest(t, relay, "GET", path, nil)
	require.Equal(t, `{"code":400,"message":"unknown payload"}`+"\n", rr.Body.String())

	path = fmt.Sprintf("/eth/v1/builder/header/%d/%s/%s", 0, forkchoiceData.ParentHash.Hex(), NewRandomValidator().Pk.String())
	rr = testRequest(t, relay, "GET", path, nil)
	require.Equal(t, ``, rr.Body.String())
	require.Equal(t, 204, rr.Code)

	err = backend.OnPayloadAttribute(&types.BuilderPayloadAttributes{})
	require.NoError(t, err)
	time.Sleep(2 * time.Second)

	path = fmt.Sprintf("/eth/v1/builder/header/%d/%s/%s", 0, forkchoiceData.ParentHash.Hex(), validator.Pk.String())
	rr = testRequest(t, relay, "GET", path, nil)
	require.Equal(t, http.StatusOK, rr.Code)

	bid := new(boostTypes.GetHeaderResponse)
	err = json.Unmarshal(rr.Body.Bytes(), bid)
	require.NoError(t, err)

	executionPayload, err := executableDataToExecutionPayload(forkchoiceData)
	require.NoError(t, err)
	expectedHeader, err := boostTypes.PayloadToPayloadHeader(executionPayload)
	require.NoError(t, err)
	expectedValue := new(boostTypes.U256Str)
	err = expectedValue.FromBig(forkchoiceBlockProfit)
	require.NoError(t, err)
	require.EqualValues(t, &boostTypes.BuilderBid{
		Header: expectedHeader,
		Value:  *expectedValue,
		Pubkey: backend.builderPublicKey,
	}, bid.Data.Message)

	require.Equal(t, forkchoiceData.ParentHash.Bytes(), bid.Data.Message.Header.ParentHash[:], "didn't build on expected parent")
	ok, err := boostTypes.VerifySignature(bid.Data.Message, backend.builderSigningDomain, backend.builderPublicKey[:], bid.Data.Signature[:])

	require.NoError(t, err)
	require.True(t, ok)
}

func TestGetPayload(t *testing.T) {
	forkchoiceData := &engine.ExecutableData{
		ParentHash:    common.HexToHash("0xafafafa"),
		FeeRecipient:  common.Address{0x01},
		LogsBloom:     types.Bloom{}.Bytes(),
		BlockHash:     common.HexToHash("0xc4a012b67027b3ab6c00acd31aeee24aa1515d6a5d7e81b0ee2e69517fdc387f"),
		BaseFeePerGas: big.NewInt(12),
		ExtraData:     []byte{},
	}

	forkchoiceBlock, err := engine.ExecutableDataToBlock(*forkchoiceData)
	require.NoError(t, err)
	forkchoiceBlockProfit := big.NewInt(10)

	backend, relay, validator := newTestBackend(t, forkchoiceData, forkchoiceBlock, forkchoiceBlockProfit)

	registerValidator(t, validator, relay)
	err = backend.OnPayloadAttribute(&types.BuilderPayloadAttributes{})
	require.NoError(t, err)
	time.Sleep(2 * time.Second)

	path := fmt.Sprintf("/eth/v1/builder/header/%d/%s/%s", 0, forkchoiceData.ParentHash.Hex(), validator.Pk.String())
	rr := testRequest(t, relay, "GET", path, nil)
	require.Equal(t, http.StatusOK, rr.Code)

	bid := new(boostTypes.GetHeaderResponse)
	err = json.Unmarshal(rr.Body.Bytes(), bid)
	require.NoError(t, err)

	// Create request payload
	msg := &boostTypes.BlindedBeaconBlock{
		Slot:          1,
		ProposerIndex: 2,
		ParentRoot:    boostTypes.Root{0x03},
		StateRoot:     boostTypes.Root{0x04},
		Body: &boostTypes.BlindedBeaconBlockBody{
			Eth1Data: &boostTypes.Eth1Data{
				DepositRoot:  boostTypes.Root{0x05},
				DepositCount: 5,
				BlockHash:    boostTypes.Hash{0x06},
			},
			SyncAggregate: &boostTypes.SyncAggregate{
				CommitteeBits:      boostTypes.CommitteeBits{0x07},
				CommitteeSignature: boostTypes.Signature{0x08},
			},
			ExecutionPayloadHeader: bid.Data.Message.Header,
		},
	}

	// TODO: test wrong signing domain
	signature, err := validator.Sign(msg, relay.proposerSigningDomain)
	require.NoError(t, err)

	// Call getPayload with invalid signature
	rr = testRequest(t, relay, "POST", "/eth/v1/builder/blinded_blocks", boostTypes.SignedBlindedBeaconBlock{
		Message:   msg,
		Signature: boostTypes.Signature{0x09},
	})
	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Equal(t, `{"code":400,"message":"invalid signature"}`+"\n", rr.Body.String())

	// Call getPayload with correct signature
	rr = testRequest(t, relay, "POST", "/eth/v1/builder/blinded_blocks", boostTypes.SignedBlindedBeaconBlock{
		Message:   msg,
		Signature: signature,
	})

	// Verify getPayload response
	require.Equal(t, http.StatusOK, rr.Code)
	getPayloadResponse := new(boostTypes.GetPayloadResponse)
	err = json.Unmarshal(rr.Body.Bytes(), getPayloadResponse)
	require.NoError(t, err)
	require.Equal(t, bid.Data.Message.Header.BlockHash, getPayloadResponse.Data.BlockHash)
}

func TestXxx(t *testing.T) {
	sk, _ := bls.GenerateRandomSecretKey()
	fmt.Println(hexutil.Encode(sk.Serialize()))
}
