package miner

import (
	"math"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/holiman/uint256"
)

func TestBuildBlockGasLimit(t *testing.T) {
	algos := []AlgoType{ALGO_GREEDY, ALGO_GREEDY_BUCKETS, ALGO_GREEDY_MULTISNAP, ALGO_GREEDY_BUCKETS_MULTISNAP}
	for _, algo := range algos {
		statedb, chData, signers := genTestSetup(GasLimit)
		env := newEnvironment(chData, statedb, signers.addresses[0], 21000, big.NewInt(1))
		txs := make(map[common.Address][]*txpool.LazyTransaction)

		tx1 := signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{})
		txs[signers.addresses[1]] = []*txpool.LazyTransaction{{
			Hash:      tx1.Hash(),
			Tx:        tx1,
			Time:      tx1.Time(),
			GasFeeCap: uint256.MustFromBig(tx1.GasFeeCap()),
			GasTipCap: uint256.MustFromBig(tx1.GasTipCap()),
			GasPrice:  uint256.MustFromBig(tx1.GasPrice()),
		}}
		tx2 := signers.signTx(2, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{})
		txs[signers.addresses[2]] = []*txpool.LazyTransaction{{
			Hash:      tx2.Hash(),
			Tx:        tx2,
			Time:      tx2.Time(),
			GasFeeCap: uint256.MustFromBig(tx2.GasFeeCap()),
			GasTipCap: uint256.MustFromBig(tx2.GasTipCap()),
			GasPrice:  uint256.MustFromBig(tx2.GasPrice()),
		}}
		tx3 := signers.signTx(3, 21000, big.NewInt(math.MaxInt), big.NewInt(math.MaxInt), signers.addresses[2], big.NewInt(math.MaxInt), []byte{})
		txs[signers.addresses[3]] = []*txpool.LazyTransaction{{
			Hash:      tx3.Hash(),
			Tx:        tx3,
			Time:      tx3.Time(),
			GasFeeCap: uint256.MustFromBig(tx3.GasFeeCap()),
			GasTipCap: uint256.MustFromBig(tx3.GasTipCap()),
			GasPrice:  uint256.MustFromBig(tx3.GasPrice()),
		}}

		var result *environment
		switch algo {
		case ALGO_GREEDY:
			builder := newGreedyBuilder(chData.chain, chData.chainConfig, &defaultAlgorithmConfig, nil, env, nil, nil)
			result, _, _ = builder.buildBlock([]types.SimulatedBundle{}, nil, txs)
		case ALGO_GREEDY_MULTISNAP:
			builder := newGreedyMultiSnapBuilder(chData.chain, chData.chainConfig, &defaultAlgorithmConfig, nil, env, nil, nil)
			result, _, _ = builder.buildBlock([]types.SimulatedBundle{}, nil, txs)
		case ALGO_GREEDY_BUCKETS:
			builder := newGreedyBucketsBuilder(chData.chain, chData.chainConfig, &defaultAlgorithmConfig, nil, env, nil, nil)
			result, _, _ = builder.buildBlock([]types.SimulatedBundle{}, nil, txs)
		case ALGO_GREEDY_BUCKETS_MULTISNAP:
			builder := newGreedyBucketsMultiSnapBuilder(chData.chain, chData.chainConfig, &defaultAlgorithmConfig, nil, env, nil, nil)
			result, _, _ = builder.buildBlock([]types.SimulatedBundle{}, nil, txs)
		}

		if result.tcount != 1 {
			t.Fatalf("Incorrect tx count [found: %d]", result.tcount)
		}
	}
}

func TestTxWithMinerFeeHeap(t *testing.T) {
	statedb, chData, signers := genTestSetup(GasLimit)

	env := newEnvironment(chData, statedb, signers.addresses[0], 21000, big.NewInt(1))

	txs := make(map[common.Address][]*txpool.LazyTransaction)

	tx1 := signers.signTx(1, 21000, big.NewInt(1), big.NewInt(5), signers.addresses[2], big.NewInt(0), []byte{})
	txs[signers.addresses[1]] = []*txpool.LazyTransaction{
		{
			Hash:      tx1.Hash(),
			Tx:        tx1,
			Time:      tx1.Time(),
			GasFeeCap: uint256.MustFromBig(tx1.GasFeeCap()),
			GasTipCap: uint256.MustFromBig(tx1.GasTipCap()),
		},
	}
	tx2 := signers.signTx(2, 21000, big.NewInt(4), big.NewInt(5), signers.addresses[2], big.NewInt(0), []byte{})
	txs[signers.addresses[2]] = []*txpool.LazyTransaction{
		{
			Hash:      tx2.Hash(),
			Tx:        tx2,
			Time:      tx2.Time(),
			GasFeeCap: uint256.MustFromBig(tx2.GasFeeCap()),
			GasTipCap: uint256.MustFromBig(tx2.GasTipCap()),
		},
	}

	bundle1 := types.SimulatedBundle{MevGasPrice: uint256.NewInt(3), OriginalBundle: types.MevBundle{Hash: common.HexToHash("0xb1")}}
	bundle2 := types.SimulatedBundle{MevGasPrice: uint256.NewInt(2), OriginalBundle: types.MevBundle{Hash: common.HexToHash("0xb2")}}

	orders := newTransactionsByPriceAndNonce(env.signer, txs, []types.SimulatedBundle{bundle2, bundle1}, nil, env.header.BaseFee)

	for {
		order := orders.Peek()
		if order == nil {
			return
		}

		if order.Tx() != nil {
			orders.Shift()
		} else if order.Bundle() != nil {
			orders.Pop()
		}
	}
}
