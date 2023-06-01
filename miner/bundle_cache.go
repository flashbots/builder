package miner

import (
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

const (
	maxHeaders = 3
)

type BundleCache struct {
	mu      sync.Mutex
	entries []*BundleCacheEntry
}

func NewBundleCache() *BundleCache {
	return &BundleCache{
		entries: make([]*BundleCacheEntry, maxHeaders),
	}
}

func (b *BundleCache) GetBundleCache(header common.Hash) *BundleCacheEntry {
	b.mu.Lock()
	defer b.mu.Unlock()

	for _, entry := range b.entries {
		if entry != nil && entry.headerHash == header {
			return entry
		}
	}
	newEntry := newCacheEntry(header)
	b.entries = b.entries[1:]
	b.entries = append(b.entries, newEntry)

	return newEntry
}

type BundleCacheEntry struct {
	mu                 sync.Mutex
	headerHash         common.Hash
	successfulBundles  map[common.Hash]*simulatedBundle
	failedBundles      map[common.Hash]struct{}
	successfulSBundles map[common.Hash]*types.SimSBundle
	failedSBundles     map[common.Hash]struct{}
}

func newCacheEntry(header common.Hash) *BundleCacheEntry {
	return &BundleCacheEntry{
		headerHash:         header,
		successfulBundles:  make(map[common.Hash]*simulatedBundle),
		failedBundles:      make(map[common.Hash]struct{}),
		successfulSBundles: make(map[common.Hash]*types.SimSBundle),
		failedSBundles:     make(map[common.Hash]struct{}),
	}
}

func (c *BundleCacheEntry) GetSimulatedBundle(bundle common.Hash) (*types.SimulatedBundle, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if simmed, ok := c.successfulBundles[bundle]; ok {
		return simmed, true
	}

	if _, ok := c.failedBundles[bundle]; ok {
		return nil, true
	}

	return nil, false
}

func (c *BundleCacheEntry) UpdateSimulatedBundles(result []*types.SimulatedBundle, bundles []types.MevBundle) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i, simBundle := range result {
		bundleHash := bundles[i].Hash
		if simBundle != nil {
			c.successfulBundles[bundleHash] = simBundle
		} else {
			c.failedBundles[bundleHash] = struct{}{}
		}
	}
}

func (c *BundleCacheEntry) GetSimSBundle(bundle common.Hash) (*types.SimSBundle, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if simmed, ok := c.successfulSBundles[bundle]; ok {
		return simmed, true
	}

	if _, ok := c.failedSBundles[bundle]; ok {
		return nil, true
	}

	return nil, false
}

func (c *BundleCacheEntry) UpdateSimSBundle(result []*types.SimSBundle, bundles []*types.SBundle) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i, simBundle := range result {
		bundleHash := bundles[i].Hash()
		if simBundle != nil {
			c.successfulSBundles[bundleHash] = simBundle
		} else {
			c.failedSBundles[bundleHash] = struct{}{}
		}
	}
}
