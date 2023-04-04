package builder

import (
	"errors"
	"fmt"
	"net/http"
	"os"

	blockvalidation "github.com/ethereum/go-ethereum/eth/block-validation"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/flashbotsextra"
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

type Service struct {
	srv     *http.Server
	builder IBuilder
}

func (s *Service) Start() error {
	if s.srv != nil {
		log.Info("Service started")
		go s.srv.ListenAndServe()
	}

	s.builder.Start()

	return nil
}

func (s *Service) Stop() error {
	if s.srv != nil {
		s.srv.Close()
	}
	s.builder.Stop()
	return nil
}

func (s *Service) PayloadAttributes(payloadAttributes *types.BuilderPayloadAttributes) error {
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

func NewService(listenAddr string, localRelay *LocalRelay, builder IBuilder) *Service {
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

func Register(stack *node.Node, backend *eth.Ethereum, cfg *Config) error {
	envBuilderSkBytes, err := hexutil.Decode(cfg.BuilderSecretKey)
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

	var beaconClient IBeaconClient
	if len(cfg.BeaconEndpoints) == 0 {
		beaconClient = &NilBeaconClient{}
	} else if len(cfg.BeaconEndpoints) == 1 {
		beaconClient = NewBeaconClient(cfg.BeaconEndpoints[0], cfg.SlotsInEpoch, cfg.SecondsInSlot)
	} else {
		beaconClient = NewMultiBeaconClient(cfg.BeaconEndpoints, cfg.SlotsInEpoch, cfg.SecondsInSlot)
	}

	var localRelay *LocalRelay
	if cfg.EnableLocalRelay {
		envRelaySkBytes, err := hexutil.Decode(cfg.RelaySecretKey)
		if err != nil {
			return errors.New("incorrect builder API secret key provided")
		}

		relaySk, err := bls.SecretKeyFromBytes(envRelaySkBytes[:])
		if err != nil {
			return errors.New("incorrect builder API secret key provided")
		}

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

	if len(cfg.SecondaryRemoteRelayEndpoints) > 0 && !(len(cfg.SecondaryRemoteRelayEndpoints) == 1 && cfg.SecondaryRemoteRelayEndpoints[0] == "") {
		secondaryRelays := make([]IRelay, len(cfg.SecondaryRemoteRelayEndpoints))
		for i, endpoint := range cfg.SecondaryRemoteRelayEndpoints {
			secondaryRelays[i] = NewRemoteRelay(endpoint, nil)
		}
		relay = NewRemoteRelayAggregator(relay, secondaryRelays)
	}

	var validator *blockvalidation.BlockValidationAPI
	if cfg.DryRun {
		var accessVerifier *blockvalidation.AccessVerifier
		if cfg.ValidationBlocklist != "" {
			accessVerifier, err = blockvalidation.NewAccessVerifierFromFile(cfg.ValidationBlocklist)
			if err != nil {
				return fmt.Errorf("failed to load validation blocklist %w", err)
			}
		}
		validator = blockvalidation.NewBlockValidationAPI(backend, accessVerifier)
	}

	// TODO: move to proper flags
	var ds flashbotsextra.IDatabaseService
	dbDSN := os.Getenv("FLASHBOTS_POSTGRES_DSN")
	if dbDSN != "" {
		ds, err = flashbotsextra.NewDatabaseService(dbDSN)
		if err != nil {
			log.Error("could not connect to the DB", "err", err)
			ds = flashbotsextra.NilDbService{}
		}
	} else {
		log.Info("db dsn is not provided, starting nil db svc")
		ds = flashbotsextra.NilDbService{}
	}

	// Bundle fetcher
	if !cfg.DisableBundleFetcher {
		mevBundleCh := make(chan []types.MevBundle)
		blockNumCh := make(chan int64)
		bundleFetcher := flashbotsextra.NewBundleFetcher(backend, ds, blockNumCh, mevBundleCh, true)
		backend.RegisterBundleFetcher(bundleFetcher)
		go bundleFetcher.Run()
	}

	ethereumService := NewEthereumService(backend)

	builderSk, err := bls.SecretKeyFromBytes(envBuilderSkBytes[:])
	if err != nil {
		return errors.New("incorrect builder API secret key provided")
	}

	builderBackend := NewBuilder(builderSk, ds, relay, builderSigningDomain, ethereumService, cfg.DryRun, validator, beaconClient)
	builderService := NewService(cfg.ListenAddr, localRelay, builderBackend)

	stack.RegisterAPIs([]rpc.API{
		{
			Namespace:     "builder",
			Version:       "1.0",
			Service:       builderService,
			Public:        true,
			Authenticated: true,
		},
	})

	stack.RegisterLifecycle(builderService)

	return nil
}
