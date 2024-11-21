package validation

import (
	"fmt"
	"net/http"

	"github.com/ethereum/go-ethereum/eth"
	validation "github.com/ethereum/go-ethereum/eth/block-validation"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/rpc"
)

type Service struct {
	srv *http.Server
}

func NewService(addr string, validationApi *validation.BlockValidationAPI) *Service {
	api := BlockValidationApi{
		validationApi: validationApi,
	}
	s := &Service{
		srv: &http.Server{
			Addr:    addr,
			Handler: api.getRouter(),
		},
	}
	return s
}

func (s *Service) Start() error {
	if s.srv != nil {
		log.Info("Service started")
		go s.srv.ListenAndServe()
	}
	return nil
}

func (s *Service) Stop() error {
	if s.srv != nil {
		s.srv.Close()
	}
	return nil
}

func Register(stack *node.Node, backend *eth.Ethereum, cfg *Config) error {
	if !cfg.Enabled {
		return nil
	}

	var err error
	var accessVerifier *validation.AccessVerifier
	if cfg.Blocklist != "" {
		accessVerifier, err = validation.NewAccessVerifierFromFile(cfg.Blocklist)
		if err != nil {
			return fmt.Errorf("failed to load validation blocklist %w", err)
		}
	}
	validationApi := validation.NewBlockValidationAPI(backend, accessVerifier, cfg.UseCoinbaseDiff, cfg.ExcludeWithdrawals)
	validationService := NewService(cfg.ListenAddr, validationApi)

	stack.RegisterAPIs([]rpc.API{
		{
			Namespace:     "validation",
			Version:       "1.0",
			Service:       validationService,
			Public:        true,
			Authenticated: true,
		},
	})

	stack.RegisterLifecycle(validationService)

	return nil
}
