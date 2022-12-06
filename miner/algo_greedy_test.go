package miner

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
)

func TestBuildBlockGasLimit(t *testing.T) {
	statedb, chData, signers := genTestSetup()

	env := newEnvironment(chData, statedb, signers.addresses[0], 21000, big.NewInt(1))

	txs := make(map[common.Address]types.Transactions)

	txs[signers.addresses[1]] = types.Transactions{
		signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{}),
	}
	txs[signers.addresses[2]] = types.Transactions{
		signers.signTx(2, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{}),
	}

	builder := newGreedyBuilder(chData.chain, chData.chainConfig, nil, env, nil)

	result, _ := builder.buildBlock([]types.SimulatedBundle{}, txs)
	log.Info("block built", "txs", len(result.txs), "gasPool", result.gasPool.Gas())
	if result.tcount != 1 {
		t.Fatal("Incorrect tx count")
	}
}

func TestTxWithMinerFeeHeap(t *testing.T) {
	statedb, chData, signers := genTestSetup()

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

	orders := types.NewTransactionsByPriceAndNonce(env.signer, txs, []types.SimulatedBundle{bundle2, bundle1}, env.header.BaseFee)

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
