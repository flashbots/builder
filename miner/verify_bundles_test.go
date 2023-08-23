package miner

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func TestVerifyBundlesAtomicity(t *testing.T) {
	tests := []struct {
		name string
		// includedBundles is a map of bundle hash to a slice of tx data that were included in the block
		includedBundles map[common.Hash][]bundleTxData
		// includedTxDataByHash is a map of tx hash to tx data that were included in the block
		includedTxDataByHash map[common.Hash]includedTxData
		// privateTxData is a map of tx hash to private tx data of private txs from failed bundles
		privateTxData map[common.Hash]privateTxData
		// mempoolTxHashes is a map of tx hashes from mempool
		mempoolTxHashes map[common.Hash]struct{}
		// expectedErr is the expected error returned by verifyBundles
		expectedErr error
	}{
		// Success cases
		{
			name: "Simple bundle with 1 tx included",
			includedBundles: map[common.Hash][]bundleTxData{
				common.HexToHash("0xb1"): {
					{hash: common.HexToHash("0xb11"), canRevert: false},
				},
			},
			includedTxDataByHash: map[common.Hash]includedTxData{
				common.HexToHash("0xb11"): {hash: common.HexToHash("0xb11"), index: 0, reverted: false},
			},
			privateTxData:   nil,
			mempoolTxHashes: nil,
			expectedErr:     nil,
		},
		{
			name: "Simple bundle included",
			includedBundles: map[common.Hash][]bundleTxData{
				common.HexToHash("0xb1"): {
					{hash: common.HexToHash("0xb11"), canRevert: false},
					{hash: common.HexToHash("0xb12"), canRevert: false},
				},
			},
			includedTxDataByHash: map[common.Hash]includedTxData{
				common.HexToHash("0xc1"):  {hash: common.HexToHash("0xc1"), index: 0, reverted: false},
				common.HexToHash("0xc2"):  {hash: common.HexToHash("0xc2"), index: 1, reverted: true},
				common.HexToHash("0xb11"): {hash: common.HexToHash("0xb11"), index: 2, reverted: false},
				common.HexToHash("0xb12"): {hash: common.HexToHash("0xb12"), index: 3, reverted: false},
				common.HexToHash("0xc3"):  {hash: common.HexToHash("0xc3"), index: 4, reverted: false},
			},
			privateTxData: nil,
			mempoolTxHashes: map[common.Hash]struct{}{
				common.HexToHash("0xc1"): {},
				common.HexToHash("0xc2"): {},
				common.HexToHash("0xc3"): {},
				// This tx is not included in the block, but it is in the mempool
				common.HexToHash("0xc4"): {},
			},
			expectedErr: nil,
		},
		{
			name: "Simple bundle included with gaps between txs",
			includedBundles: map[common.Hash][]bundleTxData{
				common.HexToHash("0xb1"): {
					{hash: common.HexToHash("0xb11"), canRevert: false},
					{hash: common.HexToHash("0xb12"), canRevert: false},
					{hash: common.HexToHash("0xb13"), canRevert: false},
				},
			},
			includedTxDataByHash: map[common.Hash]includedTxData{
				common.HexToHash("0xc1"):  {hash: common.HexToHash("0xc1"), index: 0, reverted: false},
				common.HexToHash("0xc2"):  {hash: common.HexToHash("0xc2"), index: 1, reverted: true},
				common.HexToHash("0xb11"): {hash: common.HexToHash("0xb11"), index: 2, reverted: false},
				common.HexToHash("0xc3"):  {hash: common.HexToHash("0xc3"), index: 3, reverted: false},
				common.HexToHash("0xb12"): {hash: common.HexToHash("0xb12"), index: 4, reverted: false},
				common.HexToHash("0xc4"):  {hash: common.HexToHash("0xc4"), index: 5, reverted: false},
				common.HexToHash("0xc5"):  {hash: common.HexToHash("0xc5"), index: 6, reverted: false},
				common.HexToHash("0xb13"): {hash: common.HexToHash("0xb13"), index: 7, reverted: false},
			},
			privateTxData: nil,
			mempoolTxHashes: map[common.Hash]struct{}{
				common.HexToHash("0xc1"): {},
				common.HexToHash("0xc2"): {},
				common.HexToHash("0xc3"): {},
				common.HexToHash("0xc4"): {},
				common.HexToHash("0xc5"): {},
			},
			expectedErr: nil,
		},
		{
			name: "Simple bundle included with revertible tx, tx included and reverted",
			includedBundles: map[common.Hash][]bundleTxData{
				common.HexToHash("0xb1"): {
					{hash: common.HexToHash("0xb11"), canRevert: false},
					{hash: common.HexToHash("0xb12"), canRevert: true},
					{hash: common.HexToHash("0xb13"), canRevert: false},
				},
			},
			includedTxDataByHash: map[common.Hash]includedTxData{
				common.HexToHash("0xc1"):  {hash: common.HexToHash("0xc1"), index: 0, reverted: false},
				common.HexToHash("0xc2"):  {hash: common.HexToHash("0xc2"), index: 1, reverted: true},
				common.HexToHash("0xb11"): {hash: common.HexToHash("0xb11"), index: 2, reverted: false},
				common.HexToHash("0xb12"): {hash: common.HexToHash("0xb12"), index: 3, reverted: true},
				common.HexToHash("0xb13"): {hash: common.HexToHash("0xb13"), index: 4, reverted: false},
			},
			privateTxData: nil,
			mempoolTxHashes: map[common.Hash]struct{}{
				common.HexToHash("0xc1"): {},
				common.HexToHash("0xc2"): {},
			},
			expectedErr: nil,
		},
		{
			name: "Simple bundle included with revertible tx, tx not included",
			includedBundles: map[common.Hash][]bundleTxData{
				common.HexToHash("0xb1"): {
					{hash: common.HexToHash("0xb11"), canRevert: false},
					{hash: common.HexToHash("0xb12"), canRevert: true},
					{hash: common.HexToHash("0xb13"), canRevert: false},
				},
			},
			includedTxDataByHash: map[common.Hash]includedTxData{
				common.HexToHash("0xb11"): {hash: common.HexToHash("0xb11"), index: 0, reverted: false},
				common.HexToHash("0xb13"): {hash: common.HexToHash("0xb13"), index: 1, reverted: false},
			},
			mempoolTxHashes: nil,
			privateTxData:   nil,
			expectedErr:     nil,
		},
		{
			name: "Bundle marked included but none of the txs are included (all optional)",
			includedBundles: map[common.Hash][]bundleTxData{
				common.HexToHash("0xb1"): {
					{hash: common.HexToHash("0xb11"), canRevert: true},
					{hash: common.HexToHash("0xb12"), canRevert: true},
					{hash: common.HexToHash("0xb13"), canRevert: true},
				},
			},
			includedTxDataByHash: map[common.Hash]includedTxData{
				common.HexToHash("0xc1"): {hash: common.HexToHash("0xc1"), index: 0, reverted: false},
			},
			mempoolTxHashes: map[common.Hash]struct{}{
				common.HexToHash("0xc1"): {},
			},
			privateTxData: nil,
			expectedErr:   nil,
		},
		{
			name: "Simple bundle included with all revertible tx, last of them is included as success",
			includedBundles: map[common.Hash][]bundleTxData{
				common.HexToHash("0xb1"): {
					{hash: common.HexToHash("0xb11"), canRevert: true},
					{hash: common.HexToHash("0xb12"), canRevert: true},
					{hash: common.HexToHash("0xb13"), canRevert: true},
				},
			},
			includedTxDataByHash: map[common.Hash]includedTxData{
				common.HexToHash("0xc1"):  {hash: common.HexToHash("0xc1"), index: 0, reverted: true},
				common.HexToHash("0xb13"): {hash: common.HexToHash("0xb13"), index: 1, reverted: false},
				common.HexToHash("0xc2"):  {hash: common.HexToHash("0xc2"), index: 2, reverted: true},
			},
			privateTxData: nil,
			mempoolTxHashes: map[common.Hash]struct{}{
				common.HexToHash("0xc1"): {},
				common.HexToHash("0xc2"): {},
			},
			expectedErr: nil,
		},
		{
			name: "Simple bundle included with all revertible tx, none of the txs are included",
			includedBundles: map[common.Hash][]bundleTxData{
				common.HexToHash("0xb1"): {
					{hash: common.HexToHash("0xb11"), canRevert: true},
					{hash: common.HexToHash("0xb12"), canRevert: true},
					{hash: common.HexToHash("0xb13"), canRevert: true},
				},
			},
			includedTxDataByHash: map[common.Hash]includedTxData{
				common.HexToHash("0xc1"): {hash: common.HexToHash("0xc1"), index: 0, reverted: true},
				common.HexToHash("0xc2"): {hash: common.HexToHash("0xc2"), index: 1, reverted: true},
			},
			privateTxData: nil,
			mempoolTxHashes: map[common.Hash]struct{}{
				common.HexToHash("0xc1"): {},
				common.HexToHash("0xc2"): {},
			},
			expectedErr: nil,
		},
		{
			name: "Two bundles included, both backrun one tx that is allowed to revert",
			includedBundles: map[common.Hash][]bundleTxData{
				common.HexToHash("0xb1"): {
					{hash: common.HexToHash("0xb00"), canRevert: true},
					{hash: common.HexToHash("0xb12"), canRevert: false},
				},
				common.HexToHash("0xb2"): {
					{hash: common.HexToHash("0xb00"), canRevert: true},
					{hash: common.HexToHash("0xb22"), canRevert: false},
				},
			},
			includedTxDataByHash: map[common.Hash]includedTxData{
				common.HexToHash("0xb00"): {hash: common.HexToHash("0xb00"), index: 0, reverted: false},
				common.HexToHash("0xb12"): {hash: common.HexToHash("0xb12"), index: 1, reverted: false},
				common.HexToHash("0xc1"):  {hash: common.HexToHash("0xc1"), index: 2, reverted: true},
				common.HexToHash("0xb22"): {hash: common.HexToHash("0xb22"), index: 3, reverted: false},
			},
			privateTxData: nil,
			mempoolTxHashes: map[common.Hash]struct{}{
				common.HexToHash("0xc1"): {},
			},
			expectedErr: nil,
		},
		{
			name: "Two bundles included, one have optional tx in the middle that gets included as part of other bundle",
			includedBundles: map[common.Hash][]bundleTxData{
				common.HexToHash("0xb1"): {
					{hash: common.HexToHash("0xb00"), canRevert: true},
					{hash: common.HexToHash("0xb12"), canRevert: false},
				},
				common.HexToHash("0xb2"): {
					{hash: common.HexToHash("0xb21"), canRevert: false},
					{hash: common.HexToHash("0xb00"), canRevert: true},
					{hash: common.HexToHash("0xb22"), canRevert: false},
				},
			},
			includedTxDataByHash: map[common.Hash]includedTxData{
				common.HexToHash("0xb00"): {hash: common.HexToHash("0xb00"), index: 0, reverted: false},
				common.HexToHash("0xb12"): {hash: common.HexToHash("0xb12"), index: 1, reverted: false},
				common.HexToHash("0xc1"):  {hash: common.HexToHash("0xc1"), index: 2, reverted: true},
				common.HexToHash("0xb21"): {hash: common.HexToHash("0xb21"), index: 3, reverted: false},
				common.HexToHash("0xb22"): {hash: common.HexToHash("0xb22"), index: 4, reverted: false},
			},
			privateTxData: nil,
			mempoolTxHashes: map[common.Hash]struct{}{
				common.HexToHash("0xc1"): {},
			},
			expectedErr: nil,
		},
		{
			name: "Optional tx in the middle of the bundle was included after the bundle as part of mempool",
			includedBundles: map[common.Hash][]bundleTxData{
				common.HexToHash("0xb1"): {
					{hash: common.HexToHash("0xb11"), canRevert: false},
					{hash: common.HexToHash("0xb00"), canRevert: true},
					{hash: common.HexToHash("0xb12"), canRevert: false},
				},
			},
			includedTxDataByHash: map[common.Hash]includedTxData{
				common.HexToHash("0xb11"): {hash: common.HexToHash("0xb11"), index: 0, reverted: false},
				common.HexToHash("0xb12"): {hash: common.HexToHash("0xb12"), index: 1, reverted: false},
				common.HexToHash("0xc1"):  {hash: common.HexToHash("0xc1"), index: 2, reverted: true},
				common.HexToHash("0xb00"): {hash: common.HexToHash("0xb00"), index: 3, reverted: false},
			},
			privateTxData: nil,
			mempoolTxHashes: map[common.Hash]struct{}{
				common.HexToHash("0xc1"):  {},
				common.HexToHash("0xb00"): {},
			},
			expectedErr: nil,
		},
		{
			name: "Optional tx in the middle of the bundle was included before the bundle as part of mempool",
			includedBundles: map[common.Hash][]bundleTxData{
				common.HexToHash("0xb1"): {
					{hash: common.HexToHash("0xb11"), canRevert: false},
					{hash: common.HexToHash("0xb00"), canRevert: true},
					{hash: common.HexToHash("0xb12"), canRevert: false},
				},
			},
			includedTxDataByHash: map[common.Hash]includedTxData{
				common.HexToHash("0xb00"): {hash: common.HexToHash("0xb00"), index: 0, reverted: false},
				common.HexToHash("0xb11"): {hash: common.HexToHash("0xb11"), index: 1, reverted: false},
				common.HexToHash("0xb12"): {hash: common.HexToHash("0xb12"), index: 2, reverted: false},
				common.HexToHash("0xc1"):  {hash: common.HexToHash("0xc1"), index: 3, reverted: true},
			},
			privateTxData: nil,
			mempoolTxHashes: map[common.Hash]struct{}{
				common.HexToHash("0xc1"):  {},
				common.HexToHash("0xb00"): {},
			},
			expectedErr: nil,
		},
		{
			name: "Private tx from overlapping included bundle included",
			includedBundles: map[common.Hash][]bundleTxData{
				common.HexToHash("0xb1"): {
					{hash: common.HexToHash("0xb11"), canRevert: true},
					{hash: common.HexToHash("0xb12"), canRevert: false},
				},
			},
			includedTxDataByHash: map[common.Hash]includedTxData{
				common.HexToHash("0xc1"):  {hash: common.HexToHash("0xc1"), index: 0, reverted: false},
				common.HexToHash("0xc2"):  {hash: common.HexToHash("0xc2"), index: 1, reverted: true},
				common.HexToHash("0xb11"): {hash: common.HexToHash("0xb11"), index: 2, reverted: false},
				common.HexToHash("0xb12"): {hash: common.HexToHash("0xb12"), index: 3, reverted: false},
				common.HexToHash("0xc3"):  {hash: common.HexToHash("0xc3"), index: 4, reverted: false},
			},
			privateTxData: map[common.Hash]privateTxData{
				common.HexToHash("0xb11"): {bundleHash: common.HexToHash("0xb2"), index: 2},
			},
			mempoolTxHashes: map[common.Hash]struct{}{
				common.HexToHash("0xc1"): {},
				common.HexToHash("0xc2"): {},
				common.HexToHash("0xc3"): {},
			},
			expectedErr: nil,
		},
		// Error cases
		{
			name: "Simple bundle included but with reverted txs (first tx reverted)",
			includedBundles: map[common.Hash][]bundleTxData{
				common.HexToHash("0xb1"): {
					{hash: common.HexToHash("0xb11"), canRevert: false},
					{hash: common.HexToHash("0xb12"), canRevert: false},
				},
			},
			includedTxDataByHash: map[common.Hash]includedTxData{
				common.HexToHash("0xc1"):  {hash: common.HexToHash("0xc1"), index: 0, reverted: false},
				common.HexToHash("0xc2"):  {hash: common.HexToHash("0xc2"), index: 1, reverted: true},
				common.HexToHash("0xb11"): {hash: common.HexToHash("0xb11"), index: 2, reverted: true},
				common.HexToHash("0xb12"): {hash: common.HexToHash("0xb12"), index: 3, reverted: false},
				common.HexToHash("0xc3"):  {hash: common.HexToHash("0xc3"), index: 4, reverted: false},
			},
			privateTxData: nil,
			mempoolTxHashes: map[common.Hash]struct{}{
				common.HexToHash("0xc1"): {},
				common.HexToHash("0xc2"): {},
				common.HexToHash("0xc3"): {},
			},
			expectedErr: NewErrBundleTxReverted(common.HexToHash("0xb1"), common.HexToHash("0xb11"), 0),
		},
		{
			name: "Simple bundle included but with reverted txs (second tx reverted)",
			includedBundles: map[common.Hash][]bundleTxData{
				common.HexToHash("0xb1"): {
					{hash: common.HexToHash("0xb11"), canRevert: false},
					{hash: common.HexToHash("0xb12"), canRevert: false},
				},
			},
			includedTxDataByHash: map[common.Hash]includedTxData{
				common.HexToHash("0xc1"):  {hash: common.HexToHash("0xc1"), index: 0, reverted: false},
				common.HexToHash("0xc2"):  {hash: common.HexToHash("0xc2"), index: 1, reverted: true},
				common.HexToHash("0xb11"): {hash: common.HexToHash("0xb11"), index: 2, reverted: false},
				common.HexToHash("0xb12"): {hash: common.HexToHash("0xb12"), index: 3, reverted: true},
				common.HexToHash("0xc3"):  {hash: common.HexToHash("0xc3"), index: 4, reverted: false},
			},
			privateTxData: nil,
			mempoolTxHashes: map[common.Hash]struct{}{
				common.HexToHash("0xc1"): {},
				common.HexToHash("0xc2"): {},
				common.HexToHash("0xc3"): {},
			},
			expectedErr: NewErrBundleTxReverted(common.HexToHash("0xb1"), common.HexToHash("0xb12"), 1),
		},
		{
			name: "Simple bundle included with gaps between txs (second tx reverted)",
			includedBundles: map[common.Hash][]bundleTxData{
				common.HexToHash("0xb1"): {
					{hash: common.HexToHash("0xb11"), canRevert: false},
					{hash: common.HexToHash("0xb12"), canRevert: false},
				},
			},
			includedTxDataByHash: map[common.Hash]includedTxData{
				common.HexToHash("0xc1"):  {hash: common.HexToHash("0xc1"), index: 0, reverted: false},
				common.HexToHash("0xc2"):  {hash: common.HexToHash("0xc2"), index: 1, reverted: true},
				common.HexToHash("0xb11"): {hash: common.HexToHash("0xb11"), index: 2, reverted: false},
				common.HexToHash("0xc3"):  {hash: common.HexToHash("0xc3"), index: 3, reverted: false},
				common.HexToHash("0xb12"): {hash: common.HexToHash("0xb12"), index: 4, reverted: true},
			},
			privateTxData: nil,
			mempoolTxHashes: map[common.Hash]struct{}{
				common.HexToHash("0xc1"): {},
				common.HexToHash("0xc2"): {},
				common.HexToHash("0xc3"): {},
			},
			expectedErr: NewErrBundleTxReverted(common.HexToHash("0xb1"), common.HexToHash("0xb12"), 1),
		},
		{
			name: "Simple bundle included but with incorrect order",
			includedBundles: map[common.Hash][]bundleTxData{
				common.HexToHash("0xb1"): {
					{hash: common.HexToHash("0xb11"), canRevert: false},
					{hash: common.HexToHash("0xb12"), canRevert: false},
				},
			},
			includedTxDataByHash: map[common.Hash]includedTxData{
				common.HexToHash("0xc1"):  {hash: common.HexToHash("0xc1"), index: 0, reverted: false},
				common.HexToHash("0xc2"):  {hash: common.HexToHash("0xc2"), index: 1, reverted: true},
				common.HexToHash("0xb12"): {hash: common.HexToHash("0xb12"), index: 2, reverted: false},
				common.HexToHash("0xb11"): {hash: common.HexToHash("0xb11"), index: 3, reverted: false},
				common.HexToHash("0xc3"):  {hash: common.HexToHash("0xc3"), index: 4, reverted: false},
			},
			privateTxData: nil,
			mempoolTxHashes: map[common.Hash]struct{}{
				common.HexToHash("0xc1"): {},
				common.HexToHash("0xc2"): {},
				common.HexToHash("0xc3"): {},
			},
			expectedErr: NewErrBundleTxWrongPlace(common.HexToHash("0xb1"), common.HexToHash("0xb12"), 1, 2, 4),
		},
		{
			name: "Simple bundle included but first tx missing",
			includedBundles: map[common.Hash][]bundleTxData{
				common.HexToHash("0xb1"): {
					{hash: common.HexToHash("0xb11"), canRevert: false},
					{hash: common.HexToHash("0xb12"), canRevert: false},
				},
			},
			includedTxDataByHash: map[common.Hash]includedTxData{
				common.HexToHash("0xc1"):  {hash: common.HexToHash("0xc1"), index: 0, reverted: false},
				common.HexToHash("0xc2"):  {hash: common.HexToHash("0xc2"), index: 1, reverted: true},
				common.HexToHash("0xb12"): {hash: common.HexToHash("0xb12"), index: 2, reverted: false},
				common.HexToHash("0xc3"):  {hash: common.HexToHash("0xc3"), index: 3, reverted: false},
			},
			privateTxData: nil,
			mempoolTxHashes: map[common.Hash]struct{}{
				common.HexToHash("0xc1"): {},
				common.HexToHash("0xc2"): {},
				common.HexToHash("0xc3"): {},
			},
			expectedErr: NewErrBundleTxNotFound(common.HexToHash("0xb1"), common.HexToHash("0xb11"), 0),
		},
		{
			name: "Simple bundle included but second tx missing",
			includedBundles: map[common.Hash][]bundleTxData{
				common.HexToHash("0xb1"): {
					{hash: common.HexToHash("0xb11"), canRevert: false},
					{hash: common.HexToHash("0xb12"), canRevert: false},
				},
			},
			includedTxDataByHash: map[common.Hash]includedTxData{
				common.HexToHash("0xc1"):  {hash: common.HexToHash("0xc1"), index: 0, reverted: false},
				common.HexToHash("0xc2"):  {hash: common.HexToHash("0xc2"), index: 1, reverted: true},
				common.HexToHash("0xb11"): {hash: common.HexToHash("0xb11"), index: 2, reverted: false},
				common.HexToHash("0xc3"):  {hash: common.HexToHash("0xc3"), index: 3, reverted: false},
			},
			privateTxData: nil,
			mempoolTxHashes: map[common.Hash]struct{}{
				common.HexToHash("0xc1"): {},
				common.HexToHash("0xc2"): {},
				common.HexToHash("0xc3"): {},
			},
			expectedErr: NewErrBundleTxNotFound(common.HexToHash("0xb1"), common.HexToHash("0xb12"), 1),
		},
		{
			name: "Bundle with multiple reverting txs in the front has failing tx",
			includedBundles: map[common.Hash][]bundleTxData{
				common.HexToHash("0xb1"): {
					{hash: common.HexToHash("0xb11"), canRevert: true},
					{hash: common.HexToHash("0xb12"), canRevert: true},
					{hash: common.HexToHash("0xb13"), canRevert: true},
					{hash: common.HexToHash("0xb14"), canRevert: false},
				},
			},
			includedTxDataByHash: map[common.Hash]includedTxData{
				common.HexToHash("0xc1"):  {hash: common.HexToHash("0xc1"), index: 0, reverted: false},
				common.HexToHash("0xc2"):  {hash: common.HexToHash("0xc2"), index: 1, reverted: true},
				common.HexToHash("0xb14"): {hash: common.HexToHash("0xb11"), index: 2, reverted: true},
				common.HexToHash("0xc3"):  {hash: common.HexToHash("0xc3"), index: 3, reverted: false},
			},
			privateTxData: nil,
			mempoolTxHashes: map[common.Hash]struct{}{
				common.HexToHash("0xc1"): {},
				common.HexToHash("0xc2"): {},
				common.HexToHash("0xc3"): {},
			},
			expectedErr: NewErrBundleTxReverted(common.HexToHash("0xb1"), common.HexToHash("0xb14"), 3),
		},
		{
			name:            "Private tx from failed bundles was included in a block",
			includedBundles: nil,
			includedTxDataByHash: map[common.Hash]includedTxData{
				common.HexToHash("0xc1"):  {hash: common.HexToHash("0xc1"), index: 0, reverted: false},
				common.HexToHash("0xc2"):  {hash: common.HexToHash("0xc2"), index: 1, reverted: true},
				common.HexToHash("0xb11"): {hash: common.HexToHash("0xb11"), index: 2, reverted: false},
				common.HexToHash("0xc3"):  {hash: common.HexToHash("0xc3"), index: 2, reverted: false},
			},
			privateTxData: map[common.Hash]privateTxData{
				common.HexToHash("0xb11"): {bundleHash: common.HexToHash("0xb1"), index: 2},
			},
			mempoolTxHashes: map[common.Hash]struct{}{
				common.HexToHash("0xc1"): {},
				common.HexToHash("0xc2"): {},
				common.HexToHash("0xc3"): {},
			},
			expectedErr: NewErrPrivateTxFromFailedBundle(common.HexToHash("0xb1"), common.HexToHash("0xb11"), 2),
		},
		{
			name: "Unexpected tx was included in a block",
			includedBundles: map[common.Hash][]bundleTxData{
				common.HexToHash("0xb1"): {
					{hash: common.HexToHash("0xb11"), canRevert: false},
					{hash: common.HexToHash("0xb12"), canRevert: false},
				},
			},
			includedTxDataByHash: map[common.Hash]includedTxData{
				common.HexToHash("0xc1"):  {hash: common.HexToHash("0xc1"), index: 0, reverted: false},
				common.HexToHash("0xc2"):  {hash: common.HexToHash("0xc2"), index: 1, reverted: true},
				common.HexToHash("0xb11"): {hash: common.HexToHash("0xb11"), index: 2, reverted: false},
				common.HexToHash("0xb12"): {hash: common.HexToHash("0xb12"), index: 3, reverted: false},
				common.HexToHash("0xc3"):  {hash: common.HexToHash("0xc3"), index: 4, reverted: false},
				common.HexToHash("0xd1"):  {hash: common.HexToHash("0xd1"), index: 5, reverted: false},
			},
			privateTxData: nil,
			mempoolTxHashes: map[common.Hash]struct{}{
				common.HexToHash("0xc1"): {},
				common.HexToHash("0xc2"): {},
				common.HexToHash("0xc3"): {},
			},
			expectedErr: NewErrUnexpectedTx(common.HexToHash("0xd1")),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := checkBundlesAtomicity(test.includedBundles, test.includedTxDataByHash, test.privateTxData, test.mempoolTxHashes)
			if test.expectedErr == nil {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.Equal(t, test.expectedErr, err)
			}
		})
	}
}

func TestExtractBundleDataFromUsedBundles(t *testing.T) {
	_, _, signers := genTestSetup(GasLimit)

	tx1 := signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{})
	tx2 := signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{})

	bundle := types.SimulatedBundle{
		OriginalBundle: types.MevBundle{
			Txs:               types.Transactions{tx1, tx2},
			RevertingTxHashes: []common.Hash{tx1.Hash()},
			Hash:              common.HexToHash("0xb1"),
		},
	}

	tx3 := signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{})
	tx4 := signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{})

	sbundle := &types.SBundle{
		Body: []types.BundleBody{
			{Tx: tx3, CanRevert: false},
			{
				Bundle: &types.SBundle{
					Body: []types.BundleBody{
						{Tx: tx4, CanRevert: true},
					},
				},
			},
		},
	}

	expectedResult := map[common.Hash][]bundleTxData{
		common.HexToHash("0xb1"): {
			{hash: tx1.Hash(), canRevert: true},
			{hash: tx2.Hash(), canRevert: false},
		},
		sbundle.Hash(): {
			{hash: tx3.Hash(), canRevert: false},
			{hash: tx4.Hash(), canRevert: true},
		},
	}

	result := make(map[common.Hash][]bundleTxData)
	extractBundleTxDataFromBundles([]types.SimulatedBundle{bundle}, result)
	extractBundleTxDataFromSbundles([]types.UsedSBundle{{Bundle: sbundle, Success: true}}, result, true)

	require.Equal(t, expectedResult, result)
}

func TestExtractIncludedTxDataFromEnv(t *testing.T) {
	_, _, signers := genTestSetup(GasLimit)

	tx1 := signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{})
	tx2 := signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{})

	env := &environment{
		txs: []*types.Transaction{tx1, tx2},
		receipts: []*types.Receipt{
			{TxHash: tx1.Hash(), Status: types.ReceiptStatusSuccessful},
			{TxHash: tx2.Hash(), Status: types.ReceiptStatusFailed},
		},
	}

	expectedResult := map[common.Hash]includedTxData{
		tx1.Hash(): {hash: tx1.Hash(), index: 0, reverted: false},
		tx2.Hash(): {hash: tx2.Hash(), index: 1, reverted: true},
	}

	result := extractIncludedTxDataFromEnv(env)
	require.Equal(t, expectedResult, result)
}

func TestExtractPrivateTxData(t *testing.T) {
	includedBundles := map[common.Hash][]bundleTxData{
		common.HexToHash("0xb1"): {
			{hash: common.HexToHash("0xb11"), canRevert: true},
		},
		common.HexToHash("0xb2"): {
			{hash: common.HexToHash("0xb21"), canRevert: true},
		},
	}
	allUsedBundles := map[common.Hash][]bundleTxData{
		common.HexToHash("0xb1"): {
			{hash: common.HexToHash("0xb11"), canRevert: true},
		},
		common.HexToHash("0xb2"): {
			{hash: common.HexToHash("0xb21"), canRevert: true},
		},
		common.HexToHash("0xb3"): {
			{hash: common.HexToHash("0xb31"), canRevert: true},
			{hash: common.HexToHash("0xb32"), canRevert: true},
		},
	}
	mempoolTxHashes := map[common.Hash]struct{}{
		common.HexToHash("0xb11"): {},
		common.HexToHash("0xb31"): {},
	}

	expectedResult := map[common.Hash]privateTxData{
		common.HexToHash("0xb32"): {bundleHash: common.HexToHash("0xb3"), index: 1},
	}

	result := extractPrivateTxsFromFailedBundles(includedBundles, allUsedBundles, mempoolTxHashes)

	require.Equal(t, expectedResult, result)
}

func BenchmarkVerifyBundlesAtomicity(b *testing.B) {
	_, _, signers := genTestSetup(GasLimit)

	var (
		env              = &environment{}
		committedBundles []types.SimulatedBundle
		allBundles       []types.SimulatedBundle
		mempoolTxHashes  = make(map[common.Hash]struct{})
	)

	// generate committed bundles
	for i := 0; i < 1000; i++ {
		data := crypto.Keccak256([]byte(fmt.Sprintf("ok-bundles-%x", i)))
		tx := signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), data)
		_ = tx.Hash()
		env.txs = append(env.txs, tx)
		env.receipts = append(env.receipts, &types.Receipt{TxHash: tx.Hash(), Status: types.ReceiptStatusSuccessful})
		bundleHash := common.BytesToHash(data)
		committedBundles = append(committedBundles, types.SimulatedBundle{
			OriginalBundle: types.MevBundle{
				Txs:               types.Transactions{tx},
				RevertingTxHashes: []common.Hash{},
				Hash:              bundleHash,
			},
		})
		allBundles = append(allBundles, types.SimulatedBundle{
			OriginalBundle: types.MevBundle{
				Txs:               types.Transactions{tx},
				RevertingTxHashes: []common.Hash{},
				Hash:              bundleHash,
			},
		})
	}

	// generate failed bundles
	for i := 0; i < 1000; i++ {
		data := crypto.Keccak256([]byte(fmt.Sprintf("failed-bundles-%x", i)))
		tx := signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), data)
		_ = tx.Hash()
		bundleHash := common.BytesToHash(data)
		allBundles = append(allBundles, types.SimulatedBundle{
			OriginalBundle: types.MevBundle{
				Txs:               types.Transactions{tx},
				RevertingTxHashes: []common.Hash{},
				Hash:              bundleHash,
			},
		})
	}

	// generate committed mempool txs
	for i := 0; i < 1000; i++ {
		data := crypto.Keccak256([]byte(fmt.Sprintf("ok-mempool-tx-%x", i)))
		tx := signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), data)
		hash := tx.Hash()
		env.txs = append(env.txs, tx)
		env.receipts = append(env.receipts, &types.Receipt{TxHash: hash, Status: types.ReceiptStatusSuccessful})
		mempoolTxHashes[hash] = struct{}{}
	}

	// generate failed mempool tx hashes
	for i := 0; i < 1000; i++ {
		data := crypto.Keccak256([]byte(fmt.Sprintf("failed-mempool-tx-%x", i)))
		mempoolTxHashes[common.BytesToHash(data)] = struct{}{}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := VerifyBundlesAtomicity(env, committedBundles, allBundles, nil, mempoolTxHashes)
		if err != nil {
			b.Fatal(err)
		}
	}
}
