package core

import (
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"golang.org/x/crypto/sha3"
)

type BundlePool struct {
	mevBundles []types.MevBundle

	mu sync.RWMutex
}

// NewBundlePool creates a new bundle pool to gather and filter inbound
// bundles of tx order preferences
func NewBundlePool() *BundlePool {
	return &BundlePool{}
}

// MevBundles returns a list of bundles valid for the given blockNumber/blockTimestamp
// also prunes bundles that are outdated
func (bpool *BundlePool) MevBundles(blockNumber *big.Int, blockTimestamp uint64) []types.MevBundle {
	bpool.mu.Lock()
	defer bpool.mu.Unlock()

	// returned values
	var ret []types.MevBundle
	// rolled over values
	var bundles []types.MevBundle

	for _, bundle := range bpool.mevBundles {
		// Prune outdated bundles
		if (bundle.MaxTimestamp != 0 && blockTimestamp > bundle.MaxTimestamp) || blockNumber.Cmp(bundle.BlockNumber) > 0 {
			continue
		}

		// Roll over future bundles
		if (bundle.MinTimestamp != 0 && blockTimestamp < bundle.MinTimestamp) || blockNumber.Cmp(bundle.BlockNumber) < 0 {
			bundles = append(bundles, bundle)
			continue
		}

		// return the ones which are in time
		ret = append(ret, bundle)
		// keep the bundles around internally until they need to be pruned
		bundles = append(bundles, bundle)
	}

	bpool.mevBundles = bundles

	return ret
}

// AddMevBundle adds a mev bundle to the pool
func (bpool *BundlePool) AddMevBundle(txs types.Transactions, blockNumber *big.Int, minTimestamp, maxTimestamp uint64, revertingTxHashes []common.Hash) error {
	bundleHasher := sha3.NewLegacyKeccak256()
	for _, tx := range txs {
		bundleHasher.Write(tx.Hash().Bytes())
	}
	bundleHash := common.BytesToHash(bundleHasher.Sum(nil))

	bpool.mu.Lock()
	defer bpool.mu.Unlock()

	bpool.mevBundles = append(bpool.mevBundles, types.MevBundle{
		Txs:               txs,
		BlockNumber:       blockNumber,
		MinTimestamp:      minTimestamp,
		MaxTimestamp:      maxTimestamp,
		RevertingTxHashes: revertingTxHashes,
		Hash:              bundleHash,
	})
	return nil
}

// AddMevBundles adds a mev bundles to the pool
func (bpool *BundlePool) AddMevBundles(mevBundles []types.MevBundle) error {
	bpool.mu.Lock()
	defer bpool.mu.Unlock()

	bpool.mevBundles = append(bpool.mevBundles, mevBundles...)
	return nil
}

func (pool *TxPool) MevBundles(blockNumber *big.Int, blockTimestamp uint64) []types.MevBundle {
	return pool.bundlePool.MevBundles(blockNumber, blockTimestamp)
}

func (pool *TxPool) AddMevBundle(txs types.Transactions, blockNumber *big.Int, minTimestamp, maxTimestamp uint64, revertingTxHashes []common.Hash) error {
	return pool.bundlePool.AddMevBundle(txs, blockNumber, minTimestamp, maxTimestamp, revertingTxHashes)
}

func (pool *TxPool) AddMevBundles(mevBundles []types.MevBundle) error {
	return pool.bundlePool.AddMevBundles(mevBundles)
}
