package builder

import (
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/beacon"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/log"
)

type IEthereumService interface {
	BuildBlock(attrs *BuilderPayloadAttributes) (*beacon.ExecutableDataV1, *types.Block)
	GetBlockByHash(hash common.Hash) *types.Block
	Synced() bool
}

type testEthereumService struct {
	synced             bool
	testExecutableData *beacon.ExecutableDataV1
	testBlock          *types.Block
}

func (t *testEthereumService) BuildBlock(attrs *BuilderPayloadAttributes) (*beacon.ExecutableDataV1, *types.Block) {
	return t.testExecutableData, t.testBlock
}

func (t *testEthereumService) GetBlockByHash(hash common.Hash) *types.Block { return t.testBlock }

func (t *testEthereumService) Synced() bool { return t.synced }

type EthereumService struct {
	eth *eth.Ethereum
}

func NewEthereumService(eth *eth.Ethereum) *EthereumService {
	return &EthereumService{eth: eth}
}

func (s *EthereumService) BuildBlock(attrs *BuilderPayloadAttributes) (*beacon.ExecutableDataV1, *types.Block) {
	// Send a request to generate a full block in the background.
	// The result can be obtained via the returned channel.
	resCh, err := s.eth.Miner().GetSealingBlockAsync(attrs.HeadHash, uint64(attrs.Timestamp), attrs.SuggestedFeeRecipient, attrs.GasLimit, attrs.Random, false)
	if err != nil {
		log.Error("Failed to create async sealing payload", "err", err)
		return nil, nil
	}

	timer := time.NewTimer(4 * time.Second)
	defer timer.Stop()

	select {
	case block := <-resCh:
		if block == nil {
			log.Error("received nil block from sealing work")
			return nil, nil
		}
		return beacon.BlockToExecutableData(block), block
	case <-timer.C:
		log.Error("timeout waiting for block", "parent hash", attrs.HeadHash, "slot", attrs.Slot)
		return nil, nil
	}
}

func (s *EthereumService) GetBlockByHash(hash common.Hash) *types.Block {
	return s.eth.BlockChain().GetBlockByHash(hash)
}

func (s *EthereumService) Synced() bool {
	return s.eth.Synced()
}
