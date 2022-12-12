package miner

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"math/big"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

var algoTests = []*algoTest{
	{
		Name: "simple",
		Header: &types.Header{
			GasLimit: 21_000,
		},
		Alloc: []core.GenesisAccount{
			{Balance: big.NewInt(21_000)},
			{Balance: big.NewInt(2 * 21_000)},
		},
		TxPool: func(acc accByIndex) map[int][]types.TxData {
			return map[int][]types.TxData{
				0: {
					&types.LegacyTx{Nonce: 0, To: acc(0), Gas: 21_000, GasPrice: big.NewInt(1)},
				},
				1: {
					&types.LegacyTx{Nonce: 0, To: acc(1), Gas: 21_000, GasPrice: big.NewInt(2)},
				},
			}
		},
		WantProfit: big.NewInt(2 * 21_000),
	},
	{
		Name: "lookahead",
		Header: &types.Header{
			GasLimit: 42_000,
		},
		Alloc: []core.GenesisAccount{
			{Balance: big.NewInt(21_000)},
			{Balance: big.NewInt(3 * 21_000)},
		},
		TxPool: func(acc accByIndex) map[int][]types.TxData {
			return map[int][]types.TxData{
				0: {
					&types.LegacyTx{Nonce: 0, Gas: 21_000, To: acc(0), GasPrice: big.NewInt(1)},
				},
				1: {
					&types.LegacyTx{Nonce: 0, Gas: 21_000, To: acc(1), GasPrice: big.NewInt(1)},
					&types.LegacyTx{Nonce: 1, Gas: 21_000, To: acc(1), GasPrice: big.NewInt(2)},
				},
			}
		},
		WantProfit: big.NewInt(3 * 21_000),
	},
}

func TestAlgo(t *testing.T) {
	var (
		config = params.AllEthashProtocolChanges
		signer = types.LatestSigner(config)
	)

	for _, test := range algoTests {
		t.Run(test.Name, func(t *testing.T) {
			alloc, txPool, err := test.build(signer, 1)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}

			gotProfit, err := runAlgoTest(config, alloc, txPool, test.Header, 1)
			if err != nil {
				t.Fatal(err)
			}
			if test.WantProfit.Cmp(gotProfit) != 0 {
				t.Fatalf("Profit: want %v, got %v", test.WantProfit, gotProfit)
			}
		})
	}
}

func BenchmarkAlgo(b *testing.B) {
	var (
		config = params.AllEthashProtocolChanges
		signer = types.LatestSigner(config)
		scales = []int{1, 10, 100}
	)

	for _, test := range algoTests {
		for _, scale := range scales {
			wantScaledProfit := new(big.Int).Mul(
				big.NewInt(int64(scale)),
				test.WantProfit,
			)

			b.Run(fmt.Sprintf("%s_%d", test.Name, scale), func(b *testing.B) {
				alloc, txPool, err := test.build(signer, scale)
				if err != nil {
					b.Fatalf("Build: %v", err)
				}

				b.ResetTimer()
				var txPoolCopy map[common.Address]types.Transactions
				for i := 0; i < b.N; i++ {
					// Note: copy is needed as the greedyAlgo modifies the txPool.
					func() {
						b.StopTimer()
						defer b.StartTimer()

						txPoolCopy = make(map[common.Address]types.Transactions, len(txPool))
						for addr, txs := range txPool {
							txPoolCopy[addr] = txs
						}
					}()

					gotProfit, err := runAlgoTest(config, alloc, txPoolCopy, test.Header, scale)
					if err != nil {
						b.Fatal(err)
					}
					if wantScaledProfit.Cmp(gotProfit) != 0 {
						b.Fatalf("Profit: want %v, got %v", wantScaledProfit, gotProfit)
					}
				}
			})
		}
	}
}

// runAlgo executes a single algoTest case and returns the profit.
func runAlgoTest(config *params.ChainConfig, alloc core.GenesisAlloc, txPool map[common.Address]types.Transactions, header *types.Header, scale int) (gotProfit *big.Int, err error) {
	var (
		statedb, chData = genTestSetupWithAlloc(config, alloc)
		env             = newEnvironment(chData, statedb, header.Coinbase, header.GasLimit*uint64(scale), header.BaseFee)
		builder         = newGreedyBuilder(chData.chain, chData.chainConfig, nil, env, nil, nil)

		bundles = make([]types.SimulatedBundle, 0)
	)

	// build block
	resultEnv, _ := builder.buildBlock(bundles, txPool)
	return resultEnv.profit, nil
}

// algoTest represents a block builder algorithm test case.
type algoTest struct {
	once sync.Once

	Name   string
	Header *types.Header
	Alloc  []core.GenesisAccount
	TxPool func(accByIndex) map[int][]types.TxData

	WantProfit *big.Int
}

func (test *algoTest) setDefaults() {
	// set header defaults
	if test.Header.Coinbase == (common.Address{}) {
		test.Header.Coinbase = randAddr()
	}
	if test.Header.Number == nil {
		test.Header.Number = big.NewInt(0)
	}
	if test.Header.BaseFee == nil {
		test.Header.BaseFee = big.NewInt(0)
	}
}

func (test *algoTest) build(signer types.Signer, scale int) (alloc core.GenesisAlloc, txPool map[common.Address]types.Transactions, err error) {
	test.once.Do(test.setDefaults)

	// generate accounts
	n := len(test.Alloc) // number of accounts
	addrs, prvs := genRandAccs(n * scale)

	// build alloc
	alloc = make(core.GenesisAlloc, n*scale)
	txPool = make(map[common.Address]types.Transactions)

	for s := 0; s < scale; s++ {
		for i, acc := range test.Alloc {
			alloc[addrs[s*n+i]] = acc
		}

		// define account by index function
		accByIndexFn := func(i int) *common.Address {
			if i < 0 || i >= n {
				panic(fmt.Sprintf("invalid account %d, should be in [0, %d]", i, n-1))
			}
			return &addrs[s*n+i]
		}

		// build tx pool
		preTxPool := test.TxPool(accByIndexFn)
		for i, txs := range preTxPool {
			if i < 0 || i >= n {
				panic(fmt.Sprintf("invalid account %d, should be in [0, %d]", i, n-1))
			}

			signedTxs := make(types.Transactions, len(txs))
			for j, tx := range txs {
				signedTxs[j] = types.MustSignNewTx(prvs[s*n+i], signer, tx)
			}
			txPool[addrs[s*n+i]] = signedTxs
		}
	}
	return
}

// randAddr returns a random address.
func randAddr() (addr common.Address) {
	rand.Read(addr[:])
	return addr
}

// genRandAccs generates n random accounts.
func genRandAccs(n int) ([]common.Address, []*ecdsa.PrivateKey) {
	addrs := make([]common.Address, n)
	prvs := make([]*ecdsa.PrivateKey, n)

	for i := 0; i < n; i++ {
		prv, err := crypto.GenerateKey()
		if err != nil {
			panic(fmt.Sprintf("genRandAccs: %v", err))
		}
		prvs[i] = prv
		addrs[i] = crypto.PubkeyToAddress(prv.PublicKey)
	}
	return addrs, prvs
}

type accByIndex func(int) *common.Address
