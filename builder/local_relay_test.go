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

	"github.com/ethereum/go-ethereum/core"

	"github.com/attestantio/go-builder-client/api"
	builderApiBellatrix "github.com/attestantio/go-builder-client/api/bellatrix"
	builderApiV1 "github.com/attestantio/go-builder-client/api/v1"
	builderSpec "github.com/attestantio/go-builder-client/spec"
	eth2ApiV1Bellatrix "github.com/attestantio/go-eth2-client/api/v1/bellatrix"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/flashbotsextra"
	"github.com/ethereum/go-ethereum/log"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/ssz"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

const (
	testLocalRelayValidatorGasLimit = 15_000_000
)

func newTestBackend(t *testing.T, forkchoiceData *engine.ExecutableData, block *types.Block, blockValue *big.Int) (*Builder, *LocalRelay, *ValidatorPrivateData) {
	validator := NewRandomValidator()
	sk, _ := bls.GenerateRandomSecretKey()
	bDomain := ssz.ComputeDomain(ssz.DomainTypeAppBuilder, [4]byte{0x02, 0x0, 0x0, 0x0}, phase0.Root{})
	genesisValidatorsRoot := phase0.Root(common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000"))
	cDomain := ssz.ComputeDomain(ssz.DomainTypeBeaconProposer, [4]byte{0x02, 0x0, 0x0, 0x0}, genesisValidatorsRoot)
	beaconClient := &testBeaconClient{validator: validator}
	localRelay, _ := NewLocalRelay(sk, beaconClient, bDomain, cDomain, ForkData{}, true)
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
		blockConsumer:               flashbotsextra.NilDbService{},
	}
	backend, _ := NewBuilder(builderArgs)

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
	require.Equal(t, FullValidatorData{ValidatorData: ValidatorData{Pubkey: PubkeyHex(v.Pk.String()), FeeRecipient: payload[0].Message.FeeRecipient, GasLimit: payload[0].Message.GasLimit}, Timestamp: uint64(payload[0].Message.Timestamp.Unix())}, relay.validators[PubkeyHex(v.Pk.String())])

	rr = testRequest(t, relay, "POST", "/eth/v1/builder/validators", payload)
	require.Equal(t, http.StatusOK, rr.Code)

	payload[0].Message.Timestamp = payload[0].Message.Timestamp.Add(time.Second)
	// Invalid signature
	payload[0].Signature[len(payload[0].Signature)-1] = 0x00
	rr = testRequest(t, relay, "POST", "/eth/v1/builder/validators", payload)
	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Equal(t, `{"code":400,"message":"invalid signature"}`+"\n", rr.Body.String())

	// TODO: cover all errors
}

func prepareRegistrationMessage(t *testing.T, domain phase0.Domain, v *ValidatorPrivateData) ([]builderApiV1.SignedValidatorRegistration, error) {
	var pubkey phase0.BLSPubKey
	copy(pubkey[:], v.Pk)
	require.Equal(t, []byte(v.Pk), pubkey[:])

	msg := builderApiV1.ValidatorRegistration{
		FeeRecipient: bellatrix.ExecutionAddress{0x42},
		GasLimit:     testLocalRelayValidatorGasLimit,
		Timestamp:    time.Now(),
		Pubkey:       pubkey,
	}

	signature, err := v.Sign(&msg, domain)
	require.NoError(t, err)

	return []builderApiV1.SignedValidatorRegistration{{
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
	require.Equal(t, FullValidatorData{ValidatorData: ValidatorData{Pubkey: PubkeyHex(v.Pk.String()), FeeRecipient: payload[0].Message.FeeRecipient, GasLimit: payload[0].Message.GasLimit}, Timestamp: uint64(payload[0].Message.Timestamp.Unix())}, relay.validators[PubkeyHex(v.Pk.String())])
}

func TestGetHeader(t *testing.T) {
	forkchoiceData := &engine.ExecutableData{
		ParentHash:    common.HexToHash("0xafafafa"),
		FeeRecipient:  common.Address{0x01},
		LogsBloom:     types.Bloom{0x00, 0x05, 0x10}.Bytes(),
		BlockHash:     common.HexToHash("0x64559c793c74678dff3f5d25aa328526cdb6013f13b6d989d491a8e1d9cac77a"),
		BaseFeePerGas: big.NewInt(12),
		ExtraData:     []byte{},
		GasLimit:      10_000_000,
	}

	forkchoiceBlock, err := engine.ExecutableDataToBlock(*forkchoiceData, nil, nil)
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

	attrs := &types.BuilderPayloadAttributes{}
	err = backend.OnPayloadAttribute(attrs)
	require.NoError(t, err)

	expectedGasLimit := core.CalcGasLimit(forkchoiceData.GasLimit, testLocalRelayValidatorGasLimit)
	require.Equal(t, attrs.GasLimit, expectedGasLimit)

	time.Sleep(2 * time.Second)

	path = fmt.Sprintf("/eth/v1/builder/header/%d/%s/%s", 0, forkchoiceData.ParentHash.Hex(), validator.Pk.String())
	rr = testRequest(t, relay, "GET", path, nil)
	require.Equal(t, http.StatusOK, rr.Code)

	bid := new(builderSpec.VersionedSignedBuilderBid)
	err = json.Unmarshal(rr.Body.Bytes(), bid)
	require.NoError(t, err)

	executionPayload, err := executableDataToExecutionPayload(&engine.ExecutionPayloadEnvelope{ExecutionPayload: forkchoiceData}, spec.DataVersionBellatrix)
	require.NoError(t, err)
	expectedHeader, err := PayloadToPayloadHeader(executionPayload.Bellatrix)
	require.NoError(t, err)
	expectedValue, ok := uint256.FromBig(forkchoiceBlockProfit)
	require.False(t, ok)
	require.EqualValues(t, &builderApiBellatrix.BuilderBid{
		Header: expectedHeader,
		Value:  expectedValue,
		Pubkey: backend.builderPublicKey,
	}, bid.Bellatrix.Message)

	require.Equal(t, forkchoiceData.ParentHash.Bytes(), bid.Bellatrix.Message.Header.ParentHash[:], "didn't build on expected parent")
	ok, err = ssz.VerifySignature(bid.Bellatrix.Message, backend.builderSigningDomain, backend.builderPublicKey[:], bid.Bellatrix.Signature[:])

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

	forkchoiceBlock, err := engine.ExecutableDataToBlock(*forkchoiceData, nil, nil)
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

	bid := new(builderSpec.VersionedSignedBuilderBid)
	err = json.Unmarshal(rr.Body.Bytes(), bid)
	require.NoError(t, err)

	blockHash := [32]byte{0x06}
	syncCommitteeBits := [64]byte{0x07}

	// Create request payload
	msg := &eth2ApiV1Bellatrix.BlindedBeaconBlock{
		Slot:          1,
		ProposerIndex: 2,
		ParentRoot:    phase0.Root{0x03},
		StateRoot:     phase0.Root{0x04},
		Body: &eth2ApiV1Bellatrix.BlindedBeaconBlockBody{
			ETH1Data: &phase0.ETH1Data{
				DepositRoot:  phase0.Root{0x05},
				DepositCount: 5,
				BlockHash:    blockHash[:],
			},
			ProposerSlashings: []*phase0.ProposerSlashing{},
			AttesterSlashings: []*phase0.AttesterSlashing{},
			Attestations:      []*phase0.Attestation{},
			Deposits:          []*phase0.Deposit{},
			VoluntaryExits:    []*phase0.SignedVoluntaryExit{},
			SyncAggregate: &altair.SyncAggregate{
				SyncCommitteeBits:      syncCommitteeBits[:],
				SyncCommitteeSignature: phase0.BLSSignature{0x08},
			},
			ExecutionPayloadHeader: bid.Bellatrix.Message.Header,
		},
	}

	// TODO: test wrong signing domain
	signature, err := validator.Sign(msg, relay.proposerSigningDomain)
	require.NoError(t, err)

	// Call getPayload with invalid signature
	rr = testRequest(t, relay, "POST", "/eth/v1/builder/blinded_blocks", &eth2ApiV1Bellatrix.SignedBlindedBeaconBlock{
		Message:   msg,
		Signature: phase0.BLSSignature{0x09},
	})
	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Equal(t, `{"code":400,"message":"invalid signature"}`+"\n", rr.Body.String())

	// Call getPayload with correct signature
	rr = testRequest(t, relay, "POST", "/eth/v1/builder/blinded_blocks", &eth2ApiV1Bellatrix.SignedBlindedBeaconBlock{
		Message:   msg,
		Signature: signature,
	})

	// Verify getPayload response
	require.Equal(t, http.StatusOK, rr.Code)
	getPayloadResponse := new(api.VersionedExecutionPayload)
	err = json.Unmarshal(rr.Body.Bytes(), getPayloadResponse)
	require.NoError(t, err)
	require.Equal(t, bid.Bellatrix.Message.Header.BlockHash, getPayloadResponse.Bellatrix.BlockHash)
}
