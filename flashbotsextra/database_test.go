package flashbotsextra

import (
	"math/big"
	"os"
	"testing"
	"time"

	apiv1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/require"
)

func TestDatabaseBlockInsertion(t *testing.T) {
	dsn := os.Getenv("FLASHBOTS_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip()
	}
	ds, err := NewDatabaseService(dsn)
	require.NoError(t, err)

	_, err = ds.db.Exec("delete from built_blocks_bundles where block_id = (select block_id from built_blocks where hash = '0x9cc3ee47d091fea38c0187049cae56abe4e642eeb06c4832f06ec59f5dbce7ab')")
	require.NoError(t, err)

	_, err = ds.db.Exec("delete from built_blocks_all_bundles where block_id = (select block_id from built_blocks where hash = '0x9cc3ee47d091fea38c0187049cae56abe4e642eeb06c4832f06ec59f5dbce7ab')")
	require.NoError(t, err)

	_, err = ds.db.Exec("delete from built_blocks where hash = '0x9cc3ee47d091fea38c0187049cae56abe4e642eeb06c4832f06ec59f5dbce7ab'")
	require.NoError(t, err)

	_, err = ds.db.Exec("delete from bundles where bundle_hash in ('0x0978000000000000000000000000000000000000000000000000000000000000', '0x1078000000000000000000000000000000000000000000000000000000000000', '0x0979000000000000000000000000000000000000000000000000000000000000', '0x1080000000000000000000000000000000000000000000000000000000000000')")
	require.NoError(t, err)

	block := types.NewBlock(
		&types.Header{
			ParentHash: common.HexToHash("0xafafafa"),
			Number:     big.NewInt(12),
			GasLimit:   uint64(10000),
			GasUsed:    uint64(1000),
			Time:       16000000,
			BaseFee:    big.NewInt(7),
		}, nil, nil, nil, nil)
	blockProfit := big.NewInt(10)

	simBundle1 := types.SimulatedBundle{
		MevGasPrice:       big.NewInt(9),
		TotalEth:          big.NewInt(11),
		EthSentToCoinbase: big.NewInt(10),
		TotalGasUsed:      uint64(100),
		OriginalBundle: types.MevBundle{
			Txs:               types.Transactions{types.NewTransaction(uint64(50), common.Address{0x60}, big.NewInt(19), uint64(67), big.NewInt(43), []byte{})},
			BlockNumber:       big.NewInt(12),
			MinTimestamp:      uint64(1000000),
			RevertingTxHashes: []common.Hash{{0x10, 0x17}},
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
			BlockNumber:       big.NewInt(12),
			MinTimestamp:      uint64(1000020),
			RevertingTxHashes: []common.Hash{{0x11, 0x17}},
			Hash:              common.Hash{0x10, 0x78},
		},
	}

	var bundle2Id uint64
	ds.db.Get(&bundle2Id, "insert into bundles (bundle_hash, param_signed_txs, param_block_number, param_timestamp, received_timestamp, param_reverting_tx_hashes, coinbase_diff, total_gas_used, state_block_number, gas_fees, eth_sent_to_coinbase) values (:bundle_hash, :param_signed_txs, :param_block_number, :param_timestamp, :received_timestamp, :param_reverting_tx_hashes, :coinbase_diff, :total_gas_used, :state_block_number, :gas_fees, :eth_sent_to_coinbase) on conflict (bundle_hash, param_block_number) do nothing returning id", SimulatedBundleToDbBundle(&simBundle2))

	simBundle3 := types.SimulatedBundle{
		MevGasPrice:       big.NewInt(91),
		TotalEth:          big.NewInt(111),
		EthSentToCoinbase: big.NewInt(101),
		TotalGasUsed:      uint64(101),
		OriginalBundle: types.MevBundle{
			Txs:               types.Transactions{types.NewTransaction(uint64(51), common.Address{0x62}, big.NewInt(20), uint64(68), big.NewInt(44), []byte{})},
			BlockNumber:       big.NewInt(12),
			MinTimestamp:      uint64(1000021),
			RevertingTxHashes: []common.Hash{{0x10, 0x18}},
			Hash:              common.Hash{0x09, 0x79},
		},
	}

	simBundle4 := types.SimulatedBundle{
		MevGasPrice:       big.NewInt(92),
		TotalEth:          big.NewInt(112),
		EthSentToCoinbase: big.NewInt(102),
		TotalGasUsed:      uint64(1002),
		OriginalBundle: types.MevBundle{
			Txs:               types.Transactions{types.NewTransaction(uint64(52), common.Address{0x62}, big.NewInt(110), uint64(168), big.NewInt(434), []byte{})},
			BlockNumber:       big.NewInt(12),
			MinTimestamp:      uint64(1000022),
			RevertingTxHashes: []common.Hash{{0x11, 0x19}},
			Hash:              common.Hash{0x10, 0x80},
		},
	}

	var bundle4Id uint64
	ds.db.Get(&bundle4Id, "insert into bundles (bundle_hash, param_signed_txs, param_block_number, param_timestamp, received_timestamp, param_reverting_tx_hashes, coinbase_diff, total_gas_used, state_block_number, gas_fees, eth_sent_to_coinbase) values (:bundle_hash, :param_signed_txs, :param_block_number, :param_timestamp, :received_timestamp, :param_reverting_tx_hashes, :coinbase_diff, :total_gas_used, :state_block_number, :gas_fees, :eth_sent_to_coinbase) on conflict (bundle_hash, param_block_number) do nothing returning id", SimulatedBundleToDbBundle(&simBundle4))

	usedSbundle := types.UsedSBundle{
		Bundle: &types.SBundle{
			Inclusion: types.BundleInclusion{
				BlockNumber:    5,
				MaxBlockNumber: 6,
			},
			Body: []types.BundleBody{
				{
					Tx: types.NewTransaction(uint64(53), common.Address{0x63}, big.NewInt(111), uint64(169), big.NewInt(435), []byte{})},
			},
		},
		Success: true,
	}

	bidTrace := &apiv1.BidTrace{}

	ocAt := time.Now().Add(-time.Hour).UTC()
	sealedAt := time.Now().Add(-30 * time.Minute).UTC()
	ds.ConsumeBuiltBlock(block, blockProfit, ocAt, sealedAt,
		[]types.SimulatedBundle{simBundle1, simBundle2}, []types.SimulatedBundle{simBundle1, simBundle2, simBundle3, simBundle4},
		[]types.UsedSBundle{usedSbundle}, bidTrace)

	var dbBlock BuiltBlock
	require.NoError(t, ds.db.Get(&dbBlock, "select block_id, block_number, profit, slot, hash, gas_limit, gas_used, base_fee, parent_hash, timestamp, timestamp_datetime, orders_closed_at, sealed_at from built_blocks where hash = '0x9cc3ee47d091fea38c0187049cae56abe4e642eeb06c4832f06ec59f5dbce7ab'"))
	require.Equal(t, BuiltBlock{
		BlockId:           dbBlock.BlockId,
		BlockNumber:       12,
		Profit:            "0.000000000000000010",
		Slot:              0,
		Hash:              block.Hash().String(),
		GasLimit:          block.GasLimit(),
		GasUsed:           block.GasUsed(),
		BaseFee:           7,
		ParentHash:        "0x000000000000000000000000000000000000000000000000000000000afafafa",
		Timestamp:         16000000,
		TimestampDatetime: dbBlock.TimestampDatetime,
		OrdersClosedAt:    dbBlock.OrdersClosedAt,
		SealedAt:          dbBlock.SealedAt,
	}, dbBlock)

	require.True(t, dbBlock.TimestampDatetime.Equal(time.Unix(16000000, 0)))
	require.Equal(t, ocAt.Truncate(time.Millisecond), dbBlock.OrdersClosedAt.UTC().Truncate(time.Millisecond))
	require.Equal(t, sealedAt.Truncate(time.Millisecond), dbBlock.SealedAt.UTC().Truncate(time.Millisecond))

	var bundles []DbBundle
	ds.db.Select(&bundles, "select bundle_hash, param_signed_txs, param_block_number, param_timestamp, param_reverting_tx_hashes, coinbase_diff, total_gas_used, state_block_number, gas_fees, eth_sent_to_coinbase, bundle_uuid from bundles order by param_timestamp")
	require.Len(t, bundles, 4)
	require.Equal(t, []DbBundle{SimulatedBundleToDbBundle(&simBundle1), SimulatedBundleToDbBundle(&simBundle2), SimulatedBundleToDbBundle(&simBundle3), SimulatedBundleToDbBundle(&simBundle4)}, bundles)

	var commitedBundles []string
	require.NoError(t, ds.db.Select(&commitedBundles, "select b.bundle_hash as bundle_hash from built_blocks_bundles bbb inner join bundles b on b.id = bbb.bundle_id where bbb.block_id = $1 order by b.param_timestamp", dbBlock.BlockId))
	require.Len(t, commitedBundles, 2)
	require.Equal(t, []string{simBundle1.OriginalBundle.Hash.String(), simBundle2.OriginalBundle.Hash.String()}, commitedBundles)

	var allBundles []string
	require.NoError(t, ds.db.Select(&allBundles, "select b.bundle_hash as bundle_hash from built_blocks_all_bundles bbb inner join bundles b on b.id = bbb.bundle_id where bbb.block_id = $1 order by b.param_timestamp", dbBlock.BlockId))
	require.Len(t, allBundles, 4)
	require.Equal(t, []string{simBundle1.OriginalBundle.Hash.String(), simBundle2.OriginalBundle.Hash.String(), simBundle3.OriginalBundle.Hash.String(), simBundle4.OriginalBundle.Hash.String()}, allBundles)

	var usedSbundles []DbUsedSBundle
	require.NoError(t, ds.db.Select(&usedSbundles, "select hash, inserted from sbundle_builder_used where block_id = $1", dbBlock.BlockId))
	require.Len(t, usedSbundles, 1)
	require.Equal(t, DbUsedSBundle{
		Hash:     usedSbundle.Bundle.Hash().Bytes(),
		Inserted: usedSbundle.Success,
	}, usedSbundles[0])
}

func simpleTx(nonce uint64) *types.Transaction {
	value := big.NewInt(1000000000000000) // in wei (0.001 eth)
	gasLimit := uint64(21000)             // in units
	gasPrice := big.NewInt(1000000000)

	toAddress := common.HexToAddress("0x7777492a736CD894Cb12DFE5e944047499AEF7a0")
	var data []byte
	return types.NewTx(&types.LegacyTx{
		Nonce:    nonce,
		To:       &toAddress,
		Value:    value,
		Gas:      gasLimit,
		GasPrice: gasPrice,
		Data:     data,
	})
}

func TestBundleUUIDHash(t *testing.T) {
	tx1 := simpleTx(1)
	tx2 := simpleTx(2)
	bts1, err := tx1.MarshalBinary()
	require.Nil(t, err)
	bts2, err := tx2.MarshalBinary()
	require.Nil(t, err)
	_, _ = bts1, bts2
	t.Run("no reverts", func(t *testing.T) {
		b := types.MevBundle{
			BlockNumber: big.NewInt(1),
			Hash:        common.HexToHash("0x135a7f22459b2102d51de2d6704512a03e1e2d2059c34bcbb659f4ba65e9f92c"),
		}

		require.Equal(t, "5171315f-6ba4-52b2-866e-e2390d422d81", b.ComputeUUID().String())
	})
	t.Run("one revert", func(t *testing.T) {
		b := types.MevBundle{
			BlockNumber: big.NewInt(1),
			Hash:        common.HexToHash("0x135a7f22459b2102d51de2d6704512a03e1e2d2059c34bcbb659f4ba65e9f92c"),
			RevertingTxHashes: []common.Hash{
				tx1.Hash(),
			},
		}

		require.Equal(t, "49dada39-6db2-500e-ae59-6cc18b2c19e0", b.ComputeUUID().String())
	})
}
