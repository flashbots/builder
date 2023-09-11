package miner

import (
	"math"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
)

func TestBuildBlockGasLimit(t *testing.T) {
	algos := []AlgoType{ALGO_GREEDY, ALGO_GREEDY_BUCKETS}
	for _, algo := range algos {
		statedb, chData, signers := genTestSetup()
		env := newEnvironment(chData, statedb, signers.addresses[0], 21000, big.NewInt(1))
		txs := make(map[common.Address][]*txpool.LazyTransaction)

		tx1 := signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{})
		txs[signers.addresses[1]] = []*txpool.LazyTransaction{{
			Hash:      tx1.Hash(),
			Tx:        &txpool.Transaction{Tx: tx1},
			Time:      tx1.Time(),
			GasFeeCap: tx1.GasFeeCap(),
			GasTipCap: tx1.GasTipCap(),
		}}
		tx2 := signers.signTx(2, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{})
		txs[signers.addresses[2]] = []*txpool.LazyTransaction{{
			Hash:      tx2.Hash(),
			Tx:        &txpool.Transaction{Tx: tx2},
			Time:      tx2.Time(),
			GasFeeCap: tx2.GasFeeCap(),
			GasTipCap: tx2.GasTipCap(),
		}}
		tx3 := signers.signTx(3, 21000, big.NewInt(math.MaxInt), big.NewInt(math.MaxInt), signers.addresses[2], big.NewInt(math.MaxInt), []byte{})
		txs[signers.addresses[3]] = []*txpool.LazyTransaction{{
			Hash:      tx3.Hash(),
			Tx:        &txpool.Transaction{Tx: tx3},
			Time:      tx3.Time(),
			GasFeeCap: tx3.GasFeeCap(),
			GasTipCap: tx3.GasTipCap(),
		}}

		var result *environment
		switch algo {
		case ALGO_GREEDY_BUCKETS:
			builder := newGreedyBucketsBuilder(chData.chain, chData.chainConfig, nil, nil, env, nil, nil)
			result, _, _ = builder.buildBlock([]types.SimulatedBundle{}, nil, txs)
		case ALGO_GREEDY:
			builder := newGreedyBuilder(chData.chain, chData.chainConfig, nil, nil, env, nil, nil)
			result, _, _ = builder.buildBlock([]types.SimulatedBundle{}, nil, txs)
		}

		t.Log("block built", "txs", len(result.txs), "gasPool", result.gasPool.Gas(), "algorithm", algo.String())
		if result.tcount != 1 {
			t.Fatalf("Incorrect tx count [found: %d]", result.tcount)
		}
	}
}

func TestTxWithMinerFeeHeap(t *testing.T) {
	statedb, chData, signers := genTestSetup()

	env := newEnvironment(chData, statedb, signers.addresses[0], 21000, big.NewInt(1))

	txs := make(map[common.Address][]*txpool.LazyTransaction)

	tx1 := signers.signTx(1, 21000, big.NewInt(1), big.NewInt(5), signers.addresses[2], big.NewInt(0), []byte{})
	txs[signers.addresses[1]] = []*txpool.LazyTransaction{
		{
			Hash:      tx1.Hash(),
			Tx:        &txpool.Transaction{Tx: tx1},
			Time:      tx1.Time(),
			GasFeeCap: tx1.GasFeeCap(),
			GasTipCap: tx1.GasTipCap(),
		},
	}
	tx2 := signers.signTx(2, 21000, big.NewInt(4), big.NewInt(5), signers.addresses[2], big.NewInt(0), []byte{})
	txs[signers.addresses[2]] = []*txpool.LazyTransaction{
		{
			Hash:      tx2.Hash(),
			Tx:        &txpool.Transaction{Tx: tx2},
			Time:      tx2.Time(),
			GasFeeCap: tx2.GasFeeCap(),
			GasTipCap: tx2.GasTipCap(),
		},
	}

	bundle1 := types.SimulatedBundle{MevGasPrice: big.NewInt(3), OriginalBundle: types.MevBundle{Hash: common.HexToHash("0xb1")}}
	bundle2 := types.SimulatedBundle{MevGasPrice: big.NewInt(2), OriginalBundle: types.MevBundle{Hash: common.HexToHash("0xb2")}}

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
