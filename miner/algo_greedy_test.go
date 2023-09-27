package miner

import (
	"fmt"
	"math"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

func TestBuildBlockGasLimit(t *testing.T) {
	algos := []AlgoType{ALGO_GREEDY, ALGO_GREEDY_BUCKETS, ALGO_GREEDY_MULTISNAP, ALGO_GREEDY_BUCKETS_MULTISNAP}
	for _, algo := range algos {
		statedb, chData, signers := genTestSetup(GasLimit)
		env := newEnvironment(chData, statedb, signers.addresses[0], 21000, big.NewInt(1))
		txs := make(map[common.Address]types.Transactions)

		txs[signers.addresses[1]] = types.Transactions{
			signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{}),
		}
		txs[signers.addresses[2]] = types.Transactions{
			signers.signTx(2, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{}),
		}
		txs[signers.addresses[3]] = types.Transactions{
			signers.signTx(3, 21000, big.NewInt(math.MaxInt), big.NewInt(math.MaxInt), signers.addresses[2], big.NewInt(math.MaxInt), []byte{}),
		}

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

		t.Log("block built", "txs", len(result.txs), "gasPool", result.gasPool.Gas(), "algorithm", algo.String())
		if result.tcount != 1 {
			t.Fatalf("Incorrect tx count [found: %d]", result.tcount)
		}
	}
}

func TestTxWithMinerFeeHeap(t *testing.T) {
	statedb, chData, signers := genTestSetup(GasLimit)

	env := newEnvironment(chData, statedb, signers.addresses[0], 21000, big.NewInt(1))

	txs := make(map[common.Address]types.Transactions)

	txs[signers.addresses[1]] = types.Transactions{
		signers.signTx(1, 21000, big.NewInt(1), big.NewInt(5), signers.addresses[2], big.NewInt(0), []byte{}),
	}
	txs[signers.addresses[2]] = types.Transactions{
		signers.signTx(2, 21000, big.NewInt(4), big.NewInt(5), signers.addresses[2], big.NewInt(0), []byte{}),
	}

	bundle1 := types.SimulatedBundle{MevGasPrice: big.NewInt(3), OriginalBundle: types.MevBundle{Hash: common.HexToHash("0xb1")}}
	bundle2 := types.SimulatedBundle{MevGasPrice: big.NewInt(2), OriginalBundle: types.MevBundle{Hash: common.HexToHash("0xb2")}}

	orders := types.NewTransactionsByPriceAndNonce(env.signer, txs, []types.SimulatedBundle{bundle2, bundle1}, nil, env.header.BaseFee)

	for {
		order := orders.Peek()
		if order == nil {
			return
		}

		if order.Tx() != nil {
			fmt.Println("tx", order.Tx().Hash())
			orders.Shift()
		} else if order.Bundle() != nil {
			fmt.Println("bundle", order.Bundle().OriginalBundle.Hash)
			orders.Pop()
		}
	}
}
