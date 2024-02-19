package builder

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth"
	blockvalidation "github.com/ethereum/go-ethereum/eth/block-validation"
	"github.com/ethereum/go-ethereum/flashbotsextra"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/ssz"
	"github.com/flashbots/go-utils/httplogger"
	"github.com/gorilla/mux"
	"golang.org/x/time/rate"
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

func getRelayConfig(endpoint string) (RelayConfig, error) {
	configs := strings.Split(endpoint, ";")
	if len(configs) == 0 {
		return RelayConfig{}, fmt.Errorf("empty relay endpoint %s", endpoint)
	}
	relayUrl := configs[0]
	// relay endpoint is configurated in the format URL;ssz=<value>;gzip=<value>
	// if any of them are missing, we default the config value to false
	var sszEnabled, gzipEnabled bool
	var err error

	for _, config := range configs {
		if strings.HasPrefix(config, "ssz=") {
			sszEnabled, err = strconv.ParseBool(config[4:])
			if err != nil {
				log.Info("invalid ssz config for relay", "endpoint", endpoint, "err", err)
			}
		} else if strings.HasPrefix(config, "gzip=") {
			gzipEnabled, err = strconv.ParseBool(config[5:])
			if err != nil {
				log.Info("invalid gzip config for relay", "endpoint", endpoint, "err", err)
			}
		}
	}
	return RelayConfig{
		Endpoint:    relayUrl,
		SszEnabled:  sszEnabled,
		GzipEnabled: gzipEnabled,
	}, nil
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
	builderSigningDomain := ssz.ComputeDomain(ssz.DomainTypeAppBuilder, genesisForkVersion, phase0.Root{})

	genesisValidatorsRoot := phase0.Root(common.HexToHash(cfg.GenesisValidatorsRoot))
	bellatrixForkVersionBytes, err := hexutil.Decode(cfg.BellatrixForkVersion)
	if err != nil {
		return fmt.Errorf("invalid bellatrixForkVersion: %w", err)
	}

	var bellatrixForkVersion [4]byte
	copy(bellatrixForkVersion[:], bellatrixForkVersionBytes[:4])
	proposerSigningDomain := ssz.ComputeDomain(ssz.DomainTypeBeaconProposer, bellatrixForkVersion, genesisValidatorsRoot)

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

		localRelay, err = NewLocalRelay(relaySk, beaconClient, builderSigningDomain, proposerSigningDomain, ForkData{cfg.GenesisForkVersion, cfg.BellatrixForkVersion, cfg.GenesisValidatorsRoot}, cfg.EnableValidatorChecks)
		if err != nil {
			return fmt.Errorf("failed to create local relay: %w", err)
		}
	}

	var relay IRelay
	if cfg.RemoteRelayEndpoint != "" {
		relayConfig, err := getRelayConfig(cfg.RemoteRelayEndpoint)
		if err != nil {
			return fmt.Errorf("invalid remote relay endpoint: %w", err)
		}
		relay = NewRemoteRelay(relayConfig, localRelay, cfg.EnableCancellations)
	} else if localRelay != nil {
		relay = localRelay
	} else {
		return errors.New("neither local nor remote relay specified")
	}

	if len(cfg.SecondaryRemoteRelayEndpoints) > 0 && !(len(cfg.SecondaryRemoteRelayEndpoints) == 1 && cfg.SecondaryRemoteRelayEndpoints[0] == "") {
		secondaryRelays := make([]IRelay, len(cfg.SecondaryRemoteRelayEndpoints))
		for i, endpoint := range cfg.SecondaryRemoteRelayEndpoints {
			relayConfig, err := getRelayConfig(endpoint)
			if err != nil {
				return fmt.Errorf("invalid secondary remote relay endpoint: %w", err)
			}
			secondaryRelays[i] = NewRemoteRelay(relayConfig, nil, cfg.EnableCancellations)
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
		validator = blockvalidation.NewBlockValidationAPI(backend, accessVerifier, cfg.ValidationUseCoinbaseDiff, cfg.ValidationExcludeWithdrawals)
	}

	// Set up builder rate limiter based on environment variables or CLI flags.
	// Builder rate limit parameters are flags.BuilderRateLimitDuration and flags.BuilderRateLimitMaxBurst
	duration, err := time.ParseDuration(cfg.BuilderRateLimitDuration)
	if err != nil {
		return fmt.Errorf("error parsing builder rate limit duration - %w", err)
	}

	// BuilderRateLimitMaxBurst is set to builder.RateLimitBurstDefault by default if not specified
	limiter := rate.NewLimiter(rate.Every(duration), cfg.BuilderRateLimitMaxBurst)

	var builderRateLimitInterval time.Duration
	if cfg.BuilderRateLimitResubmitInterval != "" {
		d, err := time.ParseDuration(cfg.BuilderRateLimitResubmitInterval)
		if err != nil {
			return fmt.Errorf("error parsing builder rate limit resubmit interval - %v", err)
		}
		builderRateLimitInterval = d
	} else {
		builderRateLimitInterval = RateLimitIntervalDefault
	}

	var submissionOffset time.Duration
	if offset := cfg.BuilderSubmissionOffset; offset != 0 {
		if offset < 0 {
			return fmt.Errorf("builder submission offset must be positive")
		} else if uint64(offset.Seconds()) > cfg.SecondsInSlot {
			return fmt.Errorf("builder submission offset must be less than seconds in slot")
		}
		submissionOffset = offset
	} else {
		submissionOffset = SubmissionOffsetFromEndOfSlotSecondsDefault
	}

	var blockConsumer flashbotsextra.BlockConsumer
	rpcURL := cfg.BlockProcessorURL
	if rpcURL != "" {
		blockConsumer = flashbotsextra.NewRpcBlockClient(rpcURL)
	} else {
		log.Warn("Block consumer url is empty. Built block data reporting is essentially disabled")
		blockConsumer = flashbotsextra.NilDbService{}
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

	builderArgs := BuilderArgs{
		sk:                            builderSk,
		blockConsumer:                 blockConsumer,
		ds:                            ds,
		dryRun:                        cfg.DryRun,
		eth:                           ethereumService,
		relay:                         relay,
		builderSigningDomain:          builderSigningDomain,
		builderBlockResubmitInterval:  builderRateLimitInterval,
		submissionOffsetFromEndOfSlot: submissionOffset,
		discardRevertibleTxOnErr:      cfg.DiscardRevertibleTxOnErr,
		ignoreLatePayloadAttributes:   cfg.IgnoreLatePayloadAttributes,
		validator:                     validator,
		beaconClient:                  beaconClient,
		limiter:                       limiter,
	}

	builderBackend, err := NewBuilder(builderArgs)
	if err != nil {
		return fmt.Errorf("failed to create builder backend: %w", err)
	}
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
