package builder

import (
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/params"
	"github.com/stretchr/testify/require"
)

func generatePreMergeChain(n int) (*core.Genesis, []*types.Block) {
	db := rawdb.NewMemoryDatabase()
	config := params.AllEthashProtocolChanges
	genesis := &core.Genesis{
		Config:     config,
		Alloc:      core.GenesisAlloc{},
		ExtraData:  []byte("test genesis"),
		Timestamp:  9000,
		BaseFee:    big.NewInt(params.InitialBaseFee),
		Difficulty: big.NewInt(0),
	}
	gblock := genesis.ToBlock()
	engine := ethash.NewFaker()
	blocks, _ := core.GenerateChain(config, gblock, engine, db, n, nil)
	totalDifficulty := big.NewInt(0)
	for _, b := range blocks {
		totalDifficulty.Add(totalDifficulty, b.Difficulty())
	}
	config.TerminalTotalDifficulty = totalDifficulty
	return genesis, blocks
}

// startEthService creates a full node instance for testing.
func startEthService(t *testing.T, genesis *core.Genesis, blocks []*types.Block) (*node.Node, *eth.Ethereum) {
	t.Helper()

	n, err := node.New(&node.Config{
		P2P: p2p.Config{
			ListenAddr:  "0.0.0.0:0",
			NoDiscovery: true,
			MaxPeers:    25,
		}})
	if err != nil {
		t.Fatal("can't create node:", err)
	}

	ethcfg := &ethconfig.Config{Genesis: genesis, Ethash: ethash.Config{PowMode: ethash.ModeFake}, SyncMode: downloader.SnapSync, TrieTimeout: time.Minute, TrieDirtyCache: 256, TrieCleanCache: 256}
	ethservice, err := eth.New(n, ethcfg)
	if err != nil {
		t.Fatal("can't create eth service:", err)
	}
	if err := n.Start(); err != nil {
		t.Fatal("can't start node:", err)
	}
	if _, err := ethservice.BlockChain().InsertChain(blocks); err != nil {
		n.Close()
		t.Fatal("can't import test blocks:", err)
	}
	time.Sleep(500 * time.Millisecond) // give txpool enough time to consume head event

	ethservice.SetSynced()
	return n, ethservice
}

func TestBuildBlock(t *testing.T) {
	genesis, blocks := generatePreMergeChain(10)
	n, ethservice := startEthService(t, genesis, blocks)
	defer n.Close()

	parent := ethservice.BlockChain().CurrentBlock()

	testPayloadAttributes := &types.BuilderPayloadAttributes{
		Timestamp:             hexutil.Uint64(parent.Time + 1),
		Random:                common.Hash{0x05, 0x10},
		SuggestedFeeRecipient: common.Address{0x04, 0x10},
		GasLimit:              uint64(4800000),
		Slot:                  uint64(25),
	}

	service := NewEthereumService(ethservice)
	service.eth.APIBackend.Miner().SetEtherbase(common.Address{0x05, 0x11})

	err := service.BuildBlock(testPayloadAttributes, func(block *types.Block, blockValue *big.Int, _ time.Time, _ []types.SimulatedBundle, _ []types.SimulatedBundle) {
		executableData := engine.BlockToExecutableData(block, blockValue)
		require.Equal(t, common.Address{0x05, 0x11}, executableData.ExecutionPayload.FeeRecipient)
		require.Equal(t, common.Hash{0x05, 0x10}, executableData.ExecutionPayload.Random)
		require.Equal(t, parent.Hash(), executableData.ExecutionPayload.ParentHash)
		require.Equal(t, parent.Time+1, executableData.ExecutionPayload.Timestamp)
		require.Equal(t, block.ParentHash(), parent.Hash())
		require.Equal(t, block.Hash(), executableData.ExecutionPayload.BlockHash)
		require.Equal(t, blockValue.Uint64(), uint64(0))
	})

	require.NoError(t, err)
}
