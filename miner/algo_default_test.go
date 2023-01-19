package miner

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

func TestDefaultAlgo(t *testing.T) {
	var (
		config = params.AllEthashProtocolChanges
		signer = types.LatestSigner(config)
	)

	for _, test := range algoTests {
		t.Run(test.Name, func(t *testing.T) {
			alloc, txPool, bundles, err := test.build(signer, 1)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}

			gotProfit, err := runDefaultAlgoTest(config, alloc, txPool, bundles, test.Header, 1)
			if err != nil {
				t.Fatal(err)
			}
			if test.WantProfit.Cmp(gotProfit) != 0 {
				t.Fatalf("Profit: want %v, got %v", test.WantProfit, gotProfit)
			}
		})
	}
}

// runAlgo executes a single algoTest case and returns the profit.
func runDefaultAlgoTest(config *params.ChainConfig, alloc core.GenesisAlloc, txPool map[common.Address]types.Transactions, bundles []types.MevBundle, header *types.Header, scale int) (gotProfit *big.Int, err error) {
	var (
		statedb, chData = genTestSetupWithAlloc(config, alloc)
		env             = newEnvironment(chData, statedb, header.Coinbase, header.GasLimit*uint64(scale), header.BaseFee)
		builder         = NewGreedyBuilder(chData.chain, chData.chainConfig, nil, nil, NewBundleCache())
	)

	// build block
	resultEnv, _ := BuildBlock[types.Order, types.SimulatedOrder](builder, bundles, txPool, env)
	return resultEnv.profit, nil
}
