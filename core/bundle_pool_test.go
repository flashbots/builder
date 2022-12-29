package core_test

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

type bundlesByBlock map[*big.Int]map[*ecdsa.PrivateKey][]types.MevBundle

func transaction(nonce uint64, gaslimit uint64, key *ecdsa.PrivateKey) *types.Transaction {
	return pricedTransaction(nonce, gaslimit, big.NewInt(1), key)
}

func pricedTransaction(nonce uint64, gaslimit uint64, gasprice *big.Int, key *ecdsa.PrivateKey) *types.Transaction {
	tx, err := types.SignTx(types.NewTransaction(nonce, common.Address{}, big.NewInt(100), gaslimit, gasprice, nil), types.HomesteadSigner{}, key)
	if err != nil {
		panic(err)
	}
	return tx
}

func setUpAccounts(num int) []*ecdsa.PrivateKey {
	keys := make([]*ecdsa.PrivateKey, num)

	for i := 0; i < len(keys); i++ {
		keys[i], _ = crypto.GenerateKey()
	}
	return keys
}

// returns a map of with blockNumber keys starting from 0, each containing a map of account key to a list of bundles
func setUpBundles(keys []*ecdsa.PrivateKey, numBlocks int, numBundles int, bundleSize int) bundlesByBlock {
	// store test bundles
	blockNumToAccountBundles := map[*big.Int]map[*ecdsa.PrivateKey][]types.MevBundle{}

	// iterate by block number
	for k := 0; k < numBlocks; k++ {
		blockNumber := new(big.Int).SetUint64(uint64(k))
		accountBundles := map[*ecdsa.PrivateKey][]types.MevBundle{}
		// iterate by accounts
		for i, key := range keys {
			bundles := []types.MevBundle{}
			// construct numBundles of size numBundleSize and add to map
			for j := 0; j < (numBundles); j++ {
				txs := []*types.Transaction{}
				for z := 0; z < bundleSize; z++ {
					var tx *types.Transaction
					if (i+j)%2 == 0 {
						tx = transaction(uint64(j), 25000, key)
					} else {
						tx = transaction(uint64(j), 50000, key)
					}
					txs = append(txs, tx)
				}
				bundle := types.MevBundle{
					Txs:               txs,
					BlockNumber:       blockNumber,
					MinTimestamp:      uint64(0),
					MaxTimestamp:      uint64(100),
					RevertingTxHashes: nil,
				}
				bundles = append(bundles, bundle)
			}
			// store bundles by account
			accountBundles[key] = bundles
		}
		// store all accounts bundles by block
		blockNumToAccountBundles[blockNumber] = accountBundles
	}
	return blockNumToAccountBundles
}

func Test_AddMevBundle(t *testing.T) {
	type args struct {
		txs               types.Transactions
		blockNumber       *big.Int
		minTimestamp      uint64
		maxTimestamp      uint64
		revertingTxHashes []common.Hash
	}
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Errorf("Error generating private key")
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "test",
			args: args{
				txs: types.Transactions{transaction(uint64(0), 25000, key)},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// set Up
			bpool := core.NewBundlePool()

			// Add Bundle Test
			if err := bpool.AddMevBundle(tt.args.txs, tt.args.blockNumber, tt.args.minTimestamp, tt.args.maxTimestamp, tt.args.revertingTxHashes); err != nil {
				t.Errorf("BundlePool.AddMevBundle() error = %v", err)
			}
		})
	}
}

func Test_MevBundles(t *testing.T) {
	type args struct {
		numAccounts int
		numBlocks   int
		numBundles  int
		bundleSize  int
	}
	tests := []struct {
		name    string
		wantErr bool
		args    args
	}{
		{
			name: "test",
			args: args{
				numAccounts: 10,
				numBlocks:   5,
				numBundles:  20, // bundles per account
				bundleSize:  5,
			},
		},
	}

	for _, tt := range tests {
		// make accounts
		keys := setUpAccounts(tt.args.numAccounts)
		// set up test bundles
		blockNumToAccountBundles := setUpBundles(keys, tt.args.numBlocks, tt.args.numBundles, tt.args.bundleSize)

		t.Run(tt.name, func(t *testing.T) {
			// set Up
			bpool := core.NewBundlePool()

			// iterate over blocks
			for _, blockAccountBundles := range blockNumToAccountBundles {
				// iterate over accounts in block
				for _, accountBundles := range blockAccountBundles {
					// iterate over bundles for account
					for _, bundle := range accountBundles {
						bpool.AddMevBundle(bundle.Txs, bundle.BlockNumber, bundle.MinTimestamp, bundle.MaxTimestamp, bundle.RevertingTxHashes)
					}
				}
			}

			// iterate through various testing scenarios
			for i := 0; i < tt.args.numBlocks; i++ {
				blockNumber := new(big.Int).SetInt64(int64(i))
				expectedLen := tt.args.numAccounts * tt.args.numBundles
				bundles := bpool.MevBundles(blockNumber, 0)
				// Correct Number Test
				if len(bundles) != expectedLen {
					t.Errorf("Incorrect bundle ammount for block num %d have : %d, want %d", blockNumber.Int64(), len(bundles), expectedLen)
				} else {
					fmt.Printf("Correct bundle ammount for block num %d have : %d, want %d\n", blockNumber.Int64(), len(bundles), expectedLen)
				}

				// Correct Bundle Order Test
				correctOrderMap := blockNumToAccountBundles[blockNumber]

				// iterate over over bundles in order they were added and compare to blockNumber
				i := 0
				for _, correctBlockBundles := range correctOrderMap {
					i++
					for j, bundle := range correctBlockBundles {
						if bundle.Hash != bundles[i*10+j].Hash {
							t.Errorf("Out of Order Bundles at blockNum %d", blockNumber.Int64())
						}
					}
				}

				// Old BlockNumbers Pruned Test

				// insert many bundles with low blockNumber and pull with higher blockNumber

				// grab random bundle
				randB := bundles[0]
				lowBlockNum := new(big.Int).SetInt64(int64(i - 1))
				for i := 0; i < tt.args.numBlocks; i++ {
					randB := bundles[0]
					if err := bpool.AddMevBundle(randB.Txs, lowBlockNum, randB.MinTimestamp, randB.MaxTimestamp, randB.RevertingTxHashes); (err != nil) != tt.wantErr {
						t.Errorf("BundlePool.AddMevBundle() error = %v, want none", err)
					}
				}

				// pull once to remove bundles lower than given block number
				_ = bpool.MevBundles(blockNumber, 0)
				// pull again to get bundles for desired block
				bundles3 := bpool.MevBundles(lowBlockNum, 0)

				if len(bundles3) != 0 {
					t.Errorf("Bundle failed to be evicted by blockNumber have : %d, want : %d", len(bundles3), expectedLen)
				}

				// Old Timestamps Pruned Test

				// insert many bundles with low timestamps and pull with higher timestamps

				// grab random bundle
				randB = bundles[0]
				// add to current block number with low MaxTimeStamp
				for i := 0; i < tt.args.numBlocks; i++ {
					if err := bpool.AddMevBundle(randB.Txs, blockNumber, randB.MinTimestamp, 1, randB.RevertingTxHashes); (err != nil) != tt.wantErr {
						t.Errorf("BundlePool.AddMevBundle() error = %v, want none", err)
					}
				}

				bundles2 := bpool.MevBundles(blockNumber, 5)
				if len(bundles2) != expectedLen {
					t.Errorf("Bundle failed to be evicted by MaxTimeStamp block num %d have : %d, want : %d", blockNumber.Int64(), len(bundles2), expectedLen)
				}

			}

		})

	}
}
