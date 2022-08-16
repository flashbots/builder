package builder

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/gorilla/mux"

	"github.com/flashbots/go-boost-utils/bls"
	boostTypes "github.com/flashbots/go-boost-utils/types"

	"github.com/flashbots/go-utils/httplogger"
)

const (
	_PathStatus            = "/eth/v1/builder/status"
	_PathRegisterValidator = "/eth/v1/builder/validators"
	_PathGetHeader         = "/eth/v1/builder/header/{slot:[0-9]+}/{parent_hash:0x[a-fA-F0-9]+}/{pubkey:0x[a-fA-F0-9]+}"
	_PathGetPayload        = "/eth/v1/builder/blinded_blocks"
)

type BuilderPayloadAttributes struct {
	Timestamp             hexutil.Uint64 `json:"timestamp"`
	Random                common.Hash    `json:"prevRandao"`
	SuggestedFeeRecipient common.Address `json:"suggestedFeeRecipient,omitempty"`
	Slot                  uint64         `json:"slot"`
	HeadHash              common.Hash    `json:"blockHash"`
	GasLimit              uint64
}

type Service struct {
	srv     *http.Server
	builder IBuilder
}

func (s *Service) Start() {
	if s.srv != nil {
		log.Info("Service started")
		go s.srv.ListenAndServe()
	}
}

func (s *Service) PayloadAttributes(payloadAttributes *BuilderPayloadAttributes) error {
	return s.builder.OnPayloadAttribute(payloadAttributes)
}

func getRouter(localRelay *LocalRelay) http.Handler {
	router := mux.NewRouter()

	// Add routes
	router.HandleFunc("/", localRelay.handleIndex).Methods(http.MethodGet)
	router.HandleFunc(_PathStatus, localRelay.handleStatus).Methods(http.MethodGet)
	router.HandleFunc(_PathRegisterValidator, localRelay.handleRegisterValidator).Methods(http.MethodPost)
	router.HandleFunc(_PathGetHeader, localRelay.handleGetHeader).Methods(http.MethodGet)
	router.HandleFunc(_PathGetPayload, localRelay.handleGetPayload).Methods(http.MethodPost)

	// Add logging and return router
	loggedRouter := httplogger.LoggingMiddleware(router)
	return loggedRouter
}

func NewService(listenAddr string, localRelay *LocalRelay, builder *Builder) *Service {
	var srv *http.Server
	if localRelay != nil {
		srv = &http.Server{
			Addr:    listenAddr,
			Handler: getRouter(localRelay),
			/*
			   ReadTimeout:
			   ReadHeaderTimeout:
			   WriteTimeout:
			   IdleTimeout:
			*/
		}
	}

	return &Service{
		srv:     srv,
		builder: builder,
	}
}

type BuilderConfig struct {
	Enabled               bool
	EnableValidatorChecks bool
	EnableLocalRelay      bool
	BuilderSecretKey      string
	RelaySecretKey        string
	ListenAddr            string
	GenesisForkVersion    string
	BellatrixForkVersion  string
	GenesisValidatorsRoot string
	BeaconEndpoint        string
	RemoteRelayEndpoint   string
}

func Register(stack *node.Node, backend *eth.Ethereum, cfg *BuilderConfig) error {
	envRelaySkBytes, err := hexutil.Decode(cfg.RelaySecretKey)
	if err != nil {
		return errors.New("incorrect builder API secret key provided")
	}

	relaySk, err := bls.SecretKeyFromBytes(envRelaySkBytes[:])
	if err != nil {
		return errors.New("incorrect builder API secret key provided")
	}

	envBuilderSkBytes, err := hexutil.Decode(cfg.BuilderSecretKey)
	if err != nil {
		return errors.New("incorrect builder API secret key provided")
	}

	builderSk, err := bls.SecretKeyFromBytes(envBuilderSkBytes[:])
	if err != nil {
		return errors.New("incorrect builder API secret key provided")
	}

	genesisForkVersionBytes, err := hexutil.Decode(cfg.GenesisForkVersion)
	if err != nil {
		return fmt.Errorf("invalid genesisForkVersion: %w", err)
	}

	var genesisForkVersion [4]byte
	copy(genesisForkVersion[:], genesisForkVersionBytes[:4])
	builderSigningDomain := boostTypes.ComputeDomain(boostTypes.DomainTypeAppBuilder, genesisForkVersion, boostTypes.Root{})

	genesisValidatorsRoot := boostTypes.Root(common.HexToHash(cfg.GenesisValidatorsRoot))
	bellatrixForkVersionBytes, err := hexutil.Decode(cfg.BellatrixForkVersion)
	if err != nil {
		return fmt.Errorf("invalid bellatrixForkVersion: %w", err)
	}

	var bellatrixForkVersion [4]byte
	copy(bellatrixForkVersion[:], bellatrixForkVersionBytes[:4])
	proposerSigningDomain := boostTypes.ComputeDomain(boostTypes.DomainTypeBeaconProposer, bellatrixForkVersion, genesisValidatorsRoot)

	beaconClient := NewBeaconClient(cfg.BeaconEndpoint)

	var localRelay *LocalRelay
	if cfg.EnableLocalRelay {
		localRelay = NewLocalRelay(relaySk, beaconClient, builderSigningDomain, proposerSigningDomain, ForkData{cfg.GenesisForkVersion, cfg.BellatrixForkVersion, cfg.GenesisValidatorsRoot}, cfg.EnableValidatorChecks)
	}

	var relay IRelay
	if cfg.RemoteRelayEndpoint != "" {
		relay = NewRemoteRelay(cfg.RemoteRelayEndpoint, localRelay)
	} else if localRelay != nil {
		relay = localRelay
	} else {
		return errors.New("neither local nor remote relay specified")
	}

	ethereumService := NewEthereumService(backend)

	builderBackend := NewBuilder(builderSk, beaconClient, relay, builderSigningDomain, ethereumService)
	builderService := NewService(cfg.ListenAddr, localRelay, builderBackend)
	builderService.Start()

	stack.RegisterAPIs([]rpc.API{
		{
			Namespace:     "builder",
			Version:       "1.0",
			Service:       builderService,
			Public:        true,
			Authenticated: true,
		},
	})
	return nil
}
