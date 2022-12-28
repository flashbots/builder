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
		// Trivial tx pool with 2 txs by two accounts and a block gas limit that only allows one tx
		// to be included.
		//
		// The tx paying the highest gas price should be included.
		Name:   "simple",
		Header: &types.Header{GasLimit: 21_000},
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
		// Trivial tx pool with 3 txs by two accounts and a block gas limit that only allows two txs
		// to be included. Account 1 has two pending txs of which the second one has a higher gas
		// price than the first one.
		//
		// Both txs by account 1 should be included, as they maximize the miners profit.
		Name:   "lookahead",
		Header: &types.Header{GasLimit: 63_000},
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
		WantProfit: big.NewInt(4 * 21_000),
	},
	{
		// Trivial bundle with one tx that reverts but is not allowed to revert.
		//
		// Bundle should not be included.
		Name:   "atomic-bundle-no-revert",
		Header: &types.Header{GasLimit: 50_000},
		Alloc: []core.GenesisAccount{
			{Balance: big.NewInt(50_000)},
			{Code: contractRevert},
		},
		Bundles: func(acc accByIndex, sign signByIndex, txs txByAccIndexAndNonce) []*bundle {
			return []*bundle{
				{Txs: types.Transactions{sign(0, &types.LegacyTx{Nonce: 0, Gas: 50_000, To: acc(1), GasPrice: big.NewInt(1)})}},
			}
		},
		WantProfit: big.NewInt(0),
	},
	{
		// Trivial bundle with one tx that reverts and is allowed to revert.
		//
		// Bundle should be included.
		Name:   "atomic-bundle-revert",
		Header: &types.Header{GasLimit: 50_000},
		Alloc: []core.GenesisAccount{
			{Balance: big.NewInt(50_000)},
			{Code: contractRevert},
		},
		Bundles: func(acc accByIndex, sign signByIndex, txs txByAccIndexAndNonce) []*bundle {
			return []*bundle{
				{
					Txs:                types.Transactions{sign(0, &types.LegacyTx{Nonce: 0, Gas: 50_000, To: acc(1), GasPrice: big.NewInt(1)})},
					RevertingTxIndices: []int{0},
				},
			}
		},
		WantProfit: big.NewInt(50_000),
	},
	{
		// Single failing tx that is included in the tx pool and in a bundle that is not allowed to
		// revert.
		//
		// Tx should be included.
		Name:   "simple-contradiction",
		Header: &types.Header{GasLimit: 50_000},
		Alloc: []core.GenesisAccount{
			{Balance: big.NewInt(50_000)},
			{Code: contractRevert},
		},
		TxPool: func(acc accByIndex) map[int][]types.TxData {
			return map[int][]types.TxData{
				0: {
					&types.LegacyTx{Nonce: 0, Gas: 50_000, To: acc(1), GasPrice: big.NewInt(1)},
				},
			}
		},
		Bundles: func(acc accByIndex, sign signByIndex, txs txByAccIndexAndNonce) []*bundle {
			return []*bundle{
				{Txs: types.Transactions{txs(0, 0)}},
			}
		},
		WantProfit: big.NewInt(50_000),
	},
}

func TestAlgo(t *testing.T) {
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
			simBundles, err := simulateBundles(config, test.Header, alloc, bundles)
			if err != nil {
				t.Fatalf("Simulate Bundles: %v", err)
			}

			gotProfit, err := runAlgoTest(config, alloc, txPool, simBundles, test.Header, 1)
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
				alloc, txPool, bundles, err := test.build(signer, scale)
				if err != nil {
					b.Fatalf("Build: %v", err)
				}
				simBundles, err := simulateBundles(config, test.Header, alloc, bundles)
				if err != nil {
					b.Fatalf("Simulate Bundles: %v", err)
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

					gotProfit, err := runAlgoTest(config, alloc, txPoolCopy, simBundles, test.Header, scale)
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
func runAlgoTest(config *params.ChainConfig, alloc core.GenesisAlloc, txPool map[common.Address]types.Transactions, bundles []types.SimulatedBundle, header *types.Header, scale int) (gotProfit *big.Int, err error) {
	var (
		statedb, chData = genTestSetupWithAlloc(config, alloc)
		env             = newEnvironment(chData, statedb, header.Coinbase, header.GasLimit*uint64(scale), header.BaseFee)
		builder         = newGreedyBuilder(chData.chain, chData.chainConfig, nil, env, nil)
	)

	// build block
	resultEnv, _ := builder.buildBlock(bundles, txPool)
	return resultEnv.profit, nil
}

// simulateBundles simulates bundles and returns the simulated bundles.
func simulateBundles(config *params.ChainConfig, header *types.Header, alloc core.GenesisAlloc, bundles []types.MevBundle) ([]types.SimulatedBundle, error) {
	var (
		statedb, chData = genTestSetupWithAlloc(config, alloc)
		env             = newEnvironment(chData, statedb, header.Coinbase, header.GasLimit, header.BaseFee)

		simBundles = make([]types.SimulatedBundle, 0)
	)

	for _, bundle := range bundles {
		simBundle, err := simulateBundle(env, bundle, chData, nil)
		if err != nil {
			continue
		}
		simBundles = append(simBundles, simBundle)
	}
	return simBundles, nil
}

// algoTest represents a block builder algorithm test case.
type algoTest struct {
	once sync.Once

	Name   string        // Name of the test
	Header *types.Header // Header of the block to build

	// Genesis accounts as slice.
	Alloc []core.GenesisAccount

	// TxPool creation function. The returned tx pool maps from accounts (by
	// index, referencing the Alloc slice index) to a slice of transactions.
	//
	// The function takes an accByIndex function that returns the address
	// of the GenesisAccount in the Alloc slice at the given index.
	TxPool func(accByIndex) map[int][]types.TxData

	// Bundles creation function.
	Bundles func(accByIndex, signByIndex, txByAccIndexAndNonce) []*bundle

	WantProfit *big.Int // Expected block profit
}

// setDefaults sets default values for the algoTest.
func (test *algoTest) setDefaults() {
	// set header defaults
	if test.Header == nil {
		test.Header = &types.Header{}
	}
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

// build builds the genesis alloc and tx pool from the given algoTest.
//
// The scale parameter can be used to scale up the number of the provided scenario
// of the algoTest inside the returned genesis alloc and tx pool.
func (test *algoTest) build(signer types.Signer, scale int) (alloc core.GenesisAlloc, txPool map[common.Address]types.Transactions, bundles []types.MevBundle, err error) {
	test.once.Do(test.setDefaults)

	// generate accounts
	n := len(test.Alloc) // number of accounts
	addrs, prvs := genRandAccs(n * scale)

	// build alloc
	alloc = make(core.GenesisAlloc, n*scale)
	txPool = make(map[common.Address]types.Transactions)
	bundles = make([]types.MevBundle, 0)

	for s := 0; s < scale; s++ {
		for i, acc := range test.Alloc {
			if acc.Balance == nil {
				acc.Balance = new(big.Int) // balance must be non-nil
			}
			alloc[addrs[s*n+i]] = acc
		}

		// build tx pool
		accByIndexFn := accByIndexFunc(addrs[s*n : (s+1)*n])
		if test.TxPool != nil {
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

		// build bundles
		if test.Bundles != nil {
			signByIndexFn := signByIndexFunc(prvs[s*n:(s+1)*n], signer)
			txByAccIndexAndNonceFn := txByAccIndexAndNonceFunc(addrs[s*n:(s+1)*n], txPool)
			preBundles := test.Bundles(accByIndexFn, signByIndexFn, txByAccIndexAndNonceFn)

			for _, bundle := range preBundles {
				b := bundle.toMevBundle()
				bundles = append(bundles, b)
			}
		}
	}
	return
}

// accByIndex returns the address of the genesis account with the given index.
type accByIndex func(int) *common.Address

func accByIndexFunc(accs []common.Address) accByIndex {
	return func(i int) *common.Address {
		if 0 > i || i >= len(accs) {
			panic(fmt.Sprintf("invalid account %d, should be in [0, %d]", i, len(accs)-1))
		}
		return &accs[i]
	}
}

// signByIndex signs the given transaction with the private key of the genesis
// account with the given index.
type signByIndex func(int, types.TxData) *types.Transaction

func signByIndexFunc(prvs []*ecdsa.PrivateKey, signer types.Signer) signByIndex {
	return func(i int, tx types.TxData) *types.Transaction {
		if 0 > i || i >= len(prvs) {
			panic(fmt.Sprintf("invalid private key %d, should be in [0, %d]", i, len(prvs)-1))
		}
		return types.MustSignNewTx(prvs[i], signer, tx)
	}
}

// txByAccIndexAndNonce returns the transaction with the given nonce of the
// genesis account with the given index.
type txByAccIndexAndNonce func(int, uint64) *types.Transaction

func txByAccIndexAndNonceFunc(accs []common.Address, txPool map[common.Address]types.Transactions) txByAccIndexAndNonce {
	return func(i int, nonce uint64) *types.Transaction {
		if 0 > i || i >= len(accs) {
			panic(fmt.Sprintf("invalid account %d, should be in [0, %d]", i, len(accs)-1))
		}
		addr := accs[i]
		txs := txPool[addr]

		// q&d: iterate to find nonce
		for _, tx := range txs {
			if tx.Nonce() == nonce {
				return tx
			}
		}
		panic(fmt.Sprintf("tx for account %d with nonce %d does not exist", i, nonce))
	}
}

type bundle struct {
	Txs                types.Transactions
	RevertingTxIndices []int
}

func (b *bundle) toMevBundle() types.MevBundle {
	revertingHashes := make([]common.Hash, len(b.RevertingTxIndices))
	for i, idx := range b.RevertingTxIndices {
		if 0 > idx || idx >= len(b.Txs) {
			panic(fmt.Sprintf("invalid tx index %d, should be in [0, %d]", idx, len(b.Txs)-1))
		}
		revertingHashes[i] = b.Txs[idx].Hash()
	}
	return types.MevBundle{Txs: b.Txs, RevertingTxHashes: revertingHashes}
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
