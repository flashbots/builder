package builder

import (
	"math/big"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	boostTypes "github.com/flashbots/go-boost-utils/types"
	"github.com/stretchr/testify/require"
)

func TestDatabaseBlockInsertion(t *testing.T) {
	dsn := os.Getenv("FLASHBOTS_TEST_POSTGRES_DSN")
	if dsn == "" {
		return
	}

	ds, err := NewDatabaseService(dsn)
	require.NoError(t, err)

	_, err = ds.db.Exec("insert into bundles (id, param_block_number, bundle_hash) values (10, 20, '0x1078')")
	require.NoError(t, err)

	block := types.NewBlock(
		&types.Header{
			ParentHash: common.HexToHash("0xafafafa"),
			Number:     big.NewInt(132),
			GasLimit:   uint64(10000),
			GasUsed:    uint64(1000),
			Time:       16000000,
			BaseFee:    big.NewInt(7),
		}, nil, nil, nil, nil)
	block.Profit = big.NewInt(10)

	simBundle1 := types.SimulatedBundle{
		MevGasPrice:       big.NewInt(9),
		TotalEth:          big.NewInt(11),
		EthSentToCoinbase: big.NewInt(10),
		TotalGasUsed:      uint64(100),
		OriginalBundle: types.MevBundle{
			Txs:               types.Transactions{types.NewTransaction(uint64(50), common.Address{0x60}, big.NewInt(19), uint64(67), big.NewInt(43), []byte{})},
			BlockNumber:       big.NewInt(12),
			MinTimestamp:      uint64(1000000),
			RevertingTxHashes: []common.Hash{common.Hash{0x10, 0x17}},
			Hash:              common.Hash{0x09, 0x78},
		},
	}
	simBundle2 := types.SimulatedBundle{
		MevGasPrice:       big.NewInt(90),
		TotalEth:          big.NewInt(110),
		EthSentToCoinbase: big.NewInt(100),
		TotalGasUsed:      uint64(1000),
		OriginalBundle: types.MevBundle{
			Txs:               types.Transactions{types.NewTransaction(uint64(51), common.Address{0x61}, big.NewInt(109), uint64(167), big.NewInt(433), []byte{})},
			BlockNumber:       big.NewInt(20),
			MinTimestamp:      uint64(1000020),
			RevertingTxHashes: []common.Hash{common.Hash{0x11, 0x17}},
			Hash:              common.Hash{0x10, 0x78},
		},
	}

	bidTrace := &boostTypes.BidTrace{}

	ds.ConsumeBuiltBlock(block, []types.SimulatedBundle{simBundle1, simBundle2}, bidTrace)

	var dbBlock BuiltBlock
	ds.db.Get(&dbBlock, "select * from built_blocks where hash = '0x24e6998e4d2b4fd85f7f0d27ac4b87aaf0ec18e156e4b6e194ab5dadee0cd004'")
	t.Logf("block %v", dbBlock)
}
