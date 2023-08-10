package miner

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
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
		// expectedErr is the expected error returned by verifyBundles
		expectedErr error
	}{
		// Success cases
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
			expectedErr:   nil,
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
			expectedErr:   nil,
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
			expectedErr:   nil,
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
			expectedErr:   nil,
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
			expectedErr:   nil,
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
			expectedErr:   nil,
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
			expectedErr:   NewErrBundleTxReverted(common.HexToHash("0xb1"), common.HexToHash("0xb11"), 0),
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
			expectedErr:   NewErrBundleTxReverted(common.HexToHash("0xb1"), common.HexToHash("0xb12"), 1),
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
			expectedErr:   NewErrBundleTxReverted(common.HexToHash("0xb1"), common.HexToHash("0xb12"), 1),
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
			expectedErr:   NewErrBundleTxWrongPlace(common.HexToHash("0xb1"), common.HexToHash("0xb12"), 1, 2, 4),
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
			expectedErr:   NewErrBundleTxNotFound(common.HexToHash("0xb1"), common.HexToHash("0xb11"), 0),
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
			expectedErr:   NewErrBundleTxNotFound(common.HexToHash("0xb1"), common.HexToHash("0xb12"), 1),
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
			expectedErr:   NewErrBundleTxReverted(common.HexToHash("0xb1"), common.HexToHash("0xb14"), 3),
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
			expectedErr: NewErrPrivateTxFromFailedBundle(common.HexToHash("0xb1"), common.HexToHash("0xb11"), 2),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := checkBundlesAtomicity(test.includedBundles, test.includedTxDataByHash, test.privateTxData)
			if test.expectedErr == nil {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.Equal(t, err, test.expectedErr)
			}
		})
	}
}

func TestExtractBundleDataFromUsedBundles(t *testing.T) {
	_, _, signers := genTestSetup()

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
	_, _, signers := genTestSetup()

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
