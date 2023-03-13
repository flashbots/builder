package builder

import (
	"errors"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/miner"
	"github.com/ethereum/go-ethereum/params"
)

type IEthereumService interface {
	BuildBlock(attrs *types.BuilderPayloadAttributes, sealedBlockCallback miner.BlockHookFn) error
	GetBlockByHash(hash common.Hash) *types.Block
	Config() *params.ChainConfig
	Synced() bool
}

type testEthereumService struct {
	synced             bool
	testExecutableData *engine.ExecutableData
	testBlock          *types.Block
	testBlockValue     *big.Int
	testBundlesMerged  []types.SimulatedBundle
	testAllBundles     []types.SimulatedBundle
}

func (t *testEthereumService) BuildBlock(attrs *types.BuilderPayloadAttributes, sealedBlockCallback miner.BlockHookFn) error {
	sealedBlockCallback(t.testBlock, t.testBlockValue, time.Now(), t.testBundlesMerged, t.testAllBundles)
	return nil
}

func (t *testEthereumService) GetBlockByHash(hash common.Hash) *types.Block { return t.testBlock }

func (t *testEthereumService) Config() *params.ChainConfig { return params.TestChainConfig }

func (t *testEthereumService) Synced() bool { return t.synced }

type EthereumService struct {
	eth *eth.Ethereum
}

func NewEthereumService(eth *eth.Ethereum) *EthereumService {
	return &EthereumService{eth: eth}
}

// TODO: we should move to a setup similar to catalyst local blocks & payload ids
func (s *EthereumService) BuildBlock(attrs *types.BuilderPayloadAttributes, sealedBlockCallback miner.BlockHookFn) error {
	// Send a request to generate a full block in the background.
	// The result can be obtained via the returned channel.
	args := &miner.BuildPayloadArgs{
		Parent:       attrs.HeadHash,
		Timestamp:    uint64(attrs.Timestamp),
		FeeRecipient: attrs.SuggestedFeeRecipient,
		GasLimit:     attrs.GasLimit,
		Random:       attrs.Random,
		Withdrawals:  attrs.Withdrawals,
		BlockHook:    sealedBlockCallback,
	}

	payload, err := s.eth.Miner().BuildPayload(args)
	if err != nil {
		log.Error("Failed to build payload", "err", err)
		return err
	}

	resCh := make(chan *engine.ExecutionPayloadEnvelope, 1)
	go func() {
		resCh <- payload.ResolveFull()
	}()

	timer := time.NewTimer(4 * time.Second)
	defer timer.Stop()

	select {
	case payload := <-resCh:
		if payload == nil {
			return errors.New("received nil payload from sealing work")
		}
		return nil
	case <-timer.C:
		payload.Cancel()
		log.Error("timeout waiting for block", "parent hash", attrs.HeadHash, "slot", attrs.Slot)
		return errors.New("timeout waiting for block result")
	}

}

func (s *EthereumService) GetBlockByHash(hash common.Hash) *types.Block {
	return s.eth.BlockChain().GetBlockByHash(hash)
}

func (s *EthereumService) Config() *params.ChainConfig {
	return s.eth.BlockChain().Config()
}

func (s *EthereumService) Synced() bool {
	return s.eth.Synced()
}
