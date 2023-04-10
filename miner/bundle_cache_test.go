package miner

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

func TestBundleCacheEntry(t *testing.T) {
	entry := newCacheEntry(common.HexToHash("0x01"))

	failingBundle := common.HexToHash("0xff")
	successBundle := common.HexToHash("0xaa")

	sim, found := entry.GetSimulatedBundle(failingBundle)
	if sim != nil || found {
		t.Errorf("found bundle in empty cache: %s", failingBundle)
	}
	sim, found = entry.GetSimulatedBundle(successBundle)
	if sim != nil || found {
		t.Errorf("found bundle in empty cache: %s", successBundle)
	}

	bundles := []types.MevBundle{{Hash: failingBundle}, {Hash: successBundle}}
	simResult := []*types.SimulatedBundle{nil, {OriginalBundle: bundles[1]}}
	entry.UpdateSimulatedBundles(simResult, bundles)

	sim, found = entry.GetSimulatedBundle(failingBundle)
	if sim != nil || !found {
		t.Error("incorrect failing bundle result")
	}
	sim, found = entry.GetSimulatedBundle(successBundle)
	if sim != simResult[1] || !found {
		t.Error("incorrect successful bundle result")
	}
}

func TestBundleCache(t *testing.T) {
	cache := NewBundleCache()

	header1 := common.HexToHash("0x01")
	header2 := common.HexToHash("0x02")
	header3 := common.HexToHash("0x03")
	header4 := common.HexToHash("0x04")

	cache1 := cache.GetBundleCache(header1)
	if cache1.headerHash != header1 {
		t.Error("incorrect header cache")
	}

	cache2 := cache.GetBundleCache(header2)
	if cache2.headerHash != header2 {
		t.Error("incorrect header cache")
	}

	cache2Again := cache.GetBundleCache(header2)
	if cache2 != cache2Again {
		t.Error("header cache is not reused")
	}

	cache.GetBundleCache(header3)
	cache.GetBundleCache(header4)

	cache1Again := cache.GetBundleCache(header1)
	if cache1 == cache1Again {
		t.Error("cache1 should be removed after insertions")
	}
}
