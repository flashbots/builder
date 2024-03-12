package builder

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	builderApi "github.com/attestantio/go-builder-client/api"
	builderApiBellatrix "github.com/attestantio/go-builder-client/api/bellatrix"
	builderApiV1 "github.com/attestantio/go-builder-client/api/v1"
	builderSpec "github.com/attestantio/go-builder-client/spec"
	eth2ApiV1Bellatrix "github.com/attestantio/go-eth2-client/api/v1/bellatrix"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	eth2UtilBellatrix "github.com/attestantio/go-eth2-client/util/bellatrix"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/log"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/ssz"
	"github.com/flashbots/go-boost-utils/utils"
	"github.com/gorilla/mux"
	"github.com/holiman/uint256"
)

// TODO (deneb): remove local relay

type ForkData struct {
	GenesisForkVersion    string
	BellatrixForkVersion  string
	GenesisValidatorsRoot string
}

type FullValidatorData struct {
	ValidatorData
	Timestamp uint64
}

type LocalRelay struct {
	beaconClient IBeaconClient

	relaySecretKey        *bls.SecretKey
	relayPublicKey        phase0.BLSPubKey
	serializedRelayPubkey hexutil.Bytes

	builderSigningDomain  phase0.Domain
	proposerSigningDomain phase0.Domain

	validatorsLock sync.RWMutex
	validators     map[PubkeyHex]FullValidatorData

	enableBeaconChecks bool

	bestDataLock sync.Mutex
	bestHeader   *bellatrix.ExecutionPayloadHeader
	bestPayload  *bellatrix.ExecutionPayload
	profit       *uint256.Int

	indexTemplate *template.Template
	fd            ForkData
}

func NewLocalRelay(sk *bls.SecretKey, beaconClient IBeaconClient, builderSigningDomain, proposerSigningDomain phase0.Domain, fd ForkData, enableBeaconChecks bool) (*LocalRelay, error) {
	blsPk, err := bls.PublicKeyFromSecretKey(sk)
	if err != nil {
		return nil, err
	}
	pk, err := utils.BlsPublicKeyToPublicKey(blsPk)
	if err != nil {
		return nil, err
	}

	indexTemplate, err := parseIndexTemplate()
	if err != nil {
		log.Error("could not parse index template", "err", err)
		indexTemplate = nil
	}

	return &LocalRelay{
		beaconClient: beaconClient,

		relaySecretKey: sk,
		relayPublicKey: pk,

		builderSigningDomain:  builderSigningDomain,
		proposerSigningDomain: proposerSigningDomain,
		serializedRelayPubkey: bls.PublicKeyToBytes(blsPk),

		validators: make(map[PubkeyHex]FullValidatorData),

		enableBeaconChecks: enableBeaconChecks,

		indexTemplate: indexTemplate,
		fd:            fd,
	}, nil
}

func (r *LocalRelay) Start() error {
	r.beaconClient.Start()
	return nil
}

func (r *LocalRelay) Stop() {
	r.beaconClient.Stop()
}

func (r *LocalRelay) SubmitBlock(msg *builderSpec.VersionedSubmitBlockRequest, _ ValidatorData) error {
	log.Info("submitting block to local relay", "block", msg.Bellatrix.ExecutionPayload.BlockHash.String())
	return r.submitBlock(msg.Bellatrix)
}

func (r *LocalRelay) Config() RelayConfig {
	// local relay does not need config as it is submitting to its own internal endpoint
	return RelayConfig{}
}

func (r *LocalRelay) submitBlock(msg *builderApiBellatrix.SubmitBlockRequest) error {
	header, err := PayloadToPayloadHeader(msg.ExecutionPayload)
	if err != nil {
		log.Error("could not convert payload to header", "err", err)
		return err
	}

	r.bestDataLock.Lock()
	r.bestHeader = header
	r.bestPayload = msg.ExecutionPayload
	r.profit = msg.Message.Value
	r.bestDataLock.Unlock()

	return nil
}

func (r *LocalRelay) handleRegisterValidator(w http.ResponseWriter, req *http.Request) {
	payload := []builderApiV1.SignedValidatorRegistration{}
	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		log.Error("could not decode payload", "err", err)
		respondError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	for _, registerRequest := range payload {
		if len(registerRequest.Message.Pubkey) != 48 {
			respondError(w, http.StatusBadRequest, "invalid pubkey")
			return
		}

		if len(registerRequest.Signature) != 96 {
			respondError(w, http.StatusBadRequest, "invalid signature")
			return
		}

		ok, err := ssz.VerifySignature(registerRequest.Message, r.builderSigningDomain, registerRequest.Message.Pubkey[:], registerRequest.Signature[:])
		if !ok || err != nil {
			log.Error("error verifying signature", "err", err)
			respondError(w, http.StatusBadRequest, "invalid signature")
			return
		}

		// Do not check timestamp before signature, as it would leak validator data
		if registerRequest.Message.Timestamp.Unix() > time.Now().Add(10*time.Second).Unix() {
			log.Error("invalid timestamp", "timestamp", registerRequest.Message.Timestamp)
			respondError(w, http.StatusBadRequest, "invalid payload")
			return
		}
	}

	for _, registerRequest := range payload {
		pubkeyHex := PubkeyHex(registerRequest.Message.Pubkey.String())
		if !r.beaconClient.isValidator(pubkeyHex) {
			respondError(w, http.StatusBadRequest, "not a validator")
			return
		}
	}

	r.validatorsLock.Lock()
	defer r.validatorsLock.Unlock()

	for _, registerRequest := range payload {
		pubkeyHex := PubkeyHex(registerRequest.Message.Pubkey.String())
		if previousValidatorData, ok := r.validators[pubkeyHex]; ok {
			if uint64(registerRequest.Message.Timestamp.Unix()) < previousValidatorData.Timestamp {
				respondError(w, http.StatusBadRequest, "invalid timestamp")
				return
			}

			if uint64(registerRequest.Message.Timestamp.Unix()) == previousValidatorData.Timestamp && (registerRequest.Message.FeeRecipient != previousValidatorData.FeeRecipient || registerRequest.Message.GasLimit != previousValidatorData.GasLimit) {
				respondError(w, http.StatusBadRequest, "invalid timestamp")
				return
			}
		}
	}

	for _, registerRequest := range payload {
		pubkeyHex := PubkeyHex(strings.ToLower(registerRequest.Message.Pubkey.String()))
		r.validators[pubkeyHex] = FullValidatorData{
			ValidatorData: ValidatorData{
				Pubkey:       pubkeyHex,
				FeeRecipient: registerRequest.Message.FeeRecipient,
				GasLimit:     registerRequest.Message.GasLimit,
			},
			Timestamp: uint64(registerRequest.Message.Timestamp.Unix()),
		}

		log.Info("registered validator", "pubkey", pubkeyHex, "data", r.validators[pubkeyHex])
	}

	w.WriteHeader(http.StatusOK)
}

func (r *LocalRelay) GetValidatorForSlot(nextSlot uint64) (ValidatorData, error) {
	pubkeyHex, err := r.beaconClient.getProposerForNextSlot(nextSlot)
	if err != nil {
		return ValidatorData{}, err
	}

	r.validatorsLock.RLock()
	if vd, ok := r.validators[pubkeyHex]; ok {
		r.validatorsLock.RUnlock()
		return vd.ValidatorData, nil
	}
	r.validatorsLock.RUnlock()
	log.Info("no local entry for validator", "validator", pubkeyHex)
	return ValidatorData{}, errors.New("missing validator")
}

func (r *LocalRelay) handleGetHeader(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	slot, err := strconv.Atoi(vars["slot"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "incorrect slot")
		return
	}
	parentHashHex := vars["parent_hash"]
	pubkeyHex := PubkeyHex(strings.ToLower(vars["pubkey"]))

	// Do not validate slot separately, it will create a race between slot update and proposer key
	if nextSlotProposer, err := r.beaconClient.getProposerForNextSlot(uint64(slot)); err != nil || nextSlotProposer != pubkeyHex {
		log.Error("getHeader requested for public key other than next slots proposer", "requested", pubkeyHex, "expected", nextSlotProposer)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Only check if slot is within a couple of the expected one, otherwise will force validators resync
	vd, err := r.GetValidatorForSlot(uint64(slot))
	if err != nil {
		respondError(w, http.StatusBadRequest, "unknown validator")
		return
	}
	if vd.Pubkey != pubkeyHex {
		respondError(w, http.StatusBadRequest, "unknown validator")
		return
	}

	r.bestDataLock.Lock()
	bestHeader := r.bestHeader
	profit := r.profit
	r.bestDataLock.Unlock()

	if bestHeader == nil || bestHeader.ParentHash.String() != parentHashHex {
		respondError(w, http.StatusBadRequest, "unknown payload")
		return
	}

	bid := builderApiBellatrix.BuilderBid{
		Header: bestHeader,
		Value:  profit,
		Pubkey: r.relayPublicKey,
	}
	signature, err := ssz.SignMessage(&bid, r.builderSigningDomain, r.relaySecretKey)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	response := &builderSpec.VersionedSignedBuilderBid{
		Version:   spec.DataVersionBellatrix,
		Bellatrix: &builderApiBellatrix.SignedBuilderBid{Message: &bid, Signature: signature},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}
}

func (r *LocalRelay) handleGetPayload(w http.ResponseWriter, req *http.Request) {
	payload := new(eth2ApiV1Bellatrix.SignedBlindedBeaconBlock)
	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		log.Error("failed to decode payload", "error", err)
		respondError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	if len(payload.Signature) != 96 {
		respondError(w, http.StatusBadRequest, "invalid signature")
		return
	}

	nextSlotProposerPubkeyHex, err := r.beaconClient.getProposerForNextSlot(uint64(payload.Message.Slot))
	if err != nil {
		if r.enableBeaconChecks {
			respondError(w, http.StatusBadRequest, "unknown validator")
			return
		}
	}

	nextSlotProposerPubkeyBytes, err := hexutil.Decode(string(nextSlotProposerPubkeyHex))
	if err != nil {
		if r.enableBeaconChecks {
			respondError(w, http.StatusBadRequest, "unknown validator")
			return
		}
	}

	ok, err := ssz.VerifySignature(payload.Message, r.proposerSigningDomain, nextSlotProposerPubkeyBytes[:], payload.Signature[:])
	if !ok || err != nil {
		if r.enableBeaconChecks {
			respondError(w, http.StatusBadRequest, "invalid signature")
			return
		}
	}

	r.bestDataLock.Lock()
	bestHeader := r.bestHeader
	bestPayload := r.bestPayload
	r.bestDataLock.Unlock()

	log.Info("Received blinded block", "payload", payload, "bestHeader", bestHeader)

	if bestHeader == nil || bestPayload == nil {
		respondError(w, http.StatusInternalServerError, "no payloads")
		return
	}

	if !ExecutionPayloadHeaderEqual(bestHeader, payload.Message.Body.ExecutionPayloadHeader) {
		respondError(w, http.StatusBadRequest, "unknown payload")
		return
	}

	response := &builderApi.VersionedExecutionPayload{
		Version:   spec.DataVersionBellatrix,
		Bellatrix: bestPayload,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}
}

func (r *LocalRelay) handleIndex(w http.ResponseWriter, req *http.Request) {
	if r.indexTemplate == nil {
		http.Error(w, "not available", http.StatusInternalServerError)
	}

	r.validatorsLock.RLock()
	noValidators := len(r.validators)
	r.validatorsLock.RUnlock()
	validatorsStats := fmt.Sprint(noValidators) + " validators registered"

	r.bestDataLock.Lock()
	header := r.bestHeader
	payload := r.bestPayload
	r.bestDataLock.Lock()

	headerData, err := json.MarshalIndent(header, "", "  ")
	if err != nil {
		headerData = []byte{}
	}

	payloadData, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		payloadData = []byte{}
	}

	statusData := struct {
		Pubkey                string
		ValidatorsStats       string
		GenesisForkVersion    string
		BellatrixForkVersion  string
		GenesisValidatorsRoot string
		BuilderSigningDomain  string
		ProposerSigningDomain string
		Header                string
		Blocks                string
	}{hexutil.Encode(r.serializedRelayPubkey), validatorsStats, r.fd.GenesisForkVersion, r.fd.BellatrixForkVersion, r.fd.GenesisValidatorsRoot, hexutil.Encode(r.builderSigningDomain[:]), hexutil.Encode(r.proposerSigningDomain[:]), string(headerData), string(payloadData)}

	if err := r.indexTemplate.Execute(w, statusData); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

type httpErrorResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func respondError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(httpErrorResp{code, message}); err != nil {
		http.Error(w, message, code)
	}
}

func (r *LocalRelay) handleStatus(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func ExecutionPayloadHeaderEqual(l, r *bellatrix.ExecutionPayloadHeader) bool {
	return l.ParentHash == r.ParentHash && l.FeeRecipient == r.FeeRecipient && l.StateRoot == r.StateRoot && l.ReceiptsRoot == r.ReceiptsRoot && l.LogsBloom == r.LogsBloom && l.PrevRandao == r.PrevRandao && l.BlockNumber == r.BlockNumber && l.GasLimit == r.GasLimit && l.GasUsed == r.GasUsed && l.Timestamp == r.Timestamp && l.BaseFeePerGas == r.BaseFeePerGas && bytes.Equal(l.ExtraData, r.ExtraData) && l.BlockHash == r.BlockHash && l.TransactionsRoot == r.TransactionsRoot
}

// PayloadToPayloadHeader converts an ExecutionPayload to ExecutionPayloadHeader
func PayloadToPayloadHeader(p *bellatrix.ExecutionPayload) (*bellatrix.ExecutionPayloadHeader, error) {
	if p == nil {
		return nil, errors.New("nil payload")
	}

	var txs []bellatrix.Transaction
	txs = append(txs, p.Transactions...)

	transactions := eth2UtilBellatrix.ExecutionPayloadTransactions{Transactions: txs}
	txroot, err := transactions.HashTreeRoot()
	if err != nil {
		return nil, err
	}

	return &bellatrix.ExecutionPayloadHeader{
		ParentHash:       p.ParentHash,
		FeeRecipient:     p.FeeRecipient,
		StateRoot:        p.StateRoot,
		ReceiptsRoot:     p.ReceiptsRoot,
		LogsBloom:        p.LogsBloom,
		PrevRandao:       p.PrevRandao,
		BlockNumber:      p.BlockNumber,
		GasLimit:         p.GasLimit,
		GasUsed:          p.GasUsed,
		Timestamp:        p.Timestamp,
		ExtraData:        p.ExtraData,
		BaseFeePerGas:    p.BaseFeePerGas,
		BlockHash:        p.BlockHash,
		TransactionsRoot: txroot,
	}, nil
}
