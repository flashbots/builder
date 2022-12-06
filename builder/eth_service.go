package builder

import (
	"errors"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/beacon"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/miner"
)

type IEthereumService interface {
	BuildBlock(attrs *types.BuilderPayloadAttributes, sealedBlockCallback miner.BlockHookFn) error
	GetBlockByHash(hash common.Hash) *types.Block
	Synced() bool
}

type testEthereumService struct {
	synced             bool
	testExecutableData *beacon.ExecutableDataV1
	testBlock          *types.Block
	testBundlesMerged  []types.SimulatedBundle
	testAllBundles     []types.SimulatedBundle
}

func (t *testEthereumService) BuildBlock(attrs *types.BuilderPayloadAttributes, sealedBlockCallback miner.BlockHookFn) error {
	sealedBlockCallback(t.testBlock, time.Now(), t.testBundlesMerged, t.testAllBundles)
	return nil
}

func (t *testEthereumService) GetBlockByHash(hash common.Hash) *types.Block { return t.testBlock }

func (t *testEthereumService) Synced() bool { return t.synced }

type EthereumService struct {
	eth *eth.Ethereum
}

func NewEthereumService(eth *eth.Ethereum) *EthereumService {
	return &EthereumService{eth: eth}
}

func (s *EthereumService) BuildBlock(attrs *types.BuilderPayloadAttributes, sealedBlockCallback miner.BlockHookFn) error {
	// Send a request to generate a full block in the background.
	// The result can be obtained via the returned channel.
	resCh, err := s.eth.Miner().GetSealingBlockAsync(attrs.HeadHash, uint64(attrs.Timestamp), attrs.SuggestedFeeRecipient, attrs.GasLimit, attrs.Random, false, sealedBlockCallback)
	if err != nil {
		log.Error("Failed to create async sealing payload", "err", err)
		return err
	}

	timer := time.NewTimer(4 * time.Second)
	defer timer.Stop()

	select {
	case block := <-resCh:
		if block == nil {
			return errors.New("received nil block from sealing work")
		}
		return nil
	case <-timer.C:
		log.Error("timeout waiting for block", "parent hash", attrs.HeadHash, "slot", attrs.Slot)
		return errors.New("timeout waiting for block result")
	}
}

func (s *EthereumService) GetBlockByHash(hash common.Hash) *types.Block {
	return s.eth.BlockChain().GetBlockByHash(hash)
}

func (s *EthereumService) Synced() bool {
	return s.eth.Synced()
}
