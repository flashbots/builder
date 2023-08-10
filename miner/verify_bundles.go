package miner

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// ErrBundleTxNotFound is returned when a tx is not found in the resulting block
type ErrBundleTxNotFound struct {
	BundleHash common.Hash
	TxHash     common.Hash
	// Index of the tx in the bundle
	TxIndex int
}

func NewErrBundleTxNotFound(bundleHash, txHash common.Hash, txIndex int) *ErrBundleTxNotFound {
	return &ErrBundleTxNotFound{
		BundleHash: bundleHash,
		TxHash:     txHash,
		TxIndex:    txIndex,
	}
}

func (e *ErrBundleTxNotFound) Error() string {
	return fmt.Sprintf("tx from included bundle not found tx_hash=%s, bundle_hash=%s, tx_bundle_index=%d", e.TxHash.Hex(), e.BundleHash.Hex(), e.TxIndex)
}

// ErrBundleTxReverted is returned when a tx is reverted in the resulting block, but it was not allowed to be reverted
type ErrBundleTxReverted struct {
	BundleHash common.Hash
	TxHash     common.Hash
	// Index of the tx in the bundle
	TxIndex int
}

func NewErrBundleTxReverted(bundleHash, txHash common.Hash, txIndex int) *ErrBundleTxReverted {
	return &ErrBundleTxReverted{
		BundleHash: bundleHash,
		TxHash:     txHash,
		TxIndex:    txIndex,
	}
}

func (e *ErrBundleTxReverted) Error() string {
	return fmt.Sprintf("tx from included bundle reverted tx_hash=%s, bundle_hash=%s, tx_bundle_index=%d", e.TxHash.Hex(), e.BundleHash.Hex(), e.TxIndex)
}

// ErrBundleTxWrongPlace is returned when a tx is found in the resulting block, but it is not in the right place
type ErrBundleTxWrongPlace struct {
	BundleHash common.Hash
	TxHash     common.Hash
	// Index of the tx in the bundle
	TxIndex int
	// Index of the tx in the block
	BlockIndex         int
	ExpectedBlockIndex int
}

func NewErrBundleTxWrongPlace(bundleHash, txHash common.Hash, txIndex, blockIndex, expectedBlockIndex int) *ErrBundleTxWrongPlace {
	return &ErrBundleTxWrongPlace{
		BundleHash:         bundleHash,
		TxHash:             txHash,
		TxIndex:            txIndex,
		BlockIndex:         blockIndex,
		ExpectedBlockIndex: expectedBlockIndex,
	}
}

func (e *ErrBundleTxWrongPlace) Error() string {
	return fmt.Sprintf("tx from included bundle is in wrong place tx_hash=%s, bundle_hash=%s, tx_bundle_index=%d, tx_block_index=%d, expected_block_index=%d", e.TxHash.Hex(), e.BundleHash.Hex(), e.TxIndex, e.BlockIndex, e.ExpectedBlockIndex)
}

// VerifyBundlesAtomicity checks that all txs from the included bundles are included in the block correctly
// 1. We check that all non-reverted txs from the bundle are included in the block in correct order (with possible gaps) and are not reverted
// 2. Reverted txs are allowed to be not included in the block
// NOTE: we only verify bundles that were committed in the block but not all bundles that we tried to include
func VerifyBundlesAtomicity(env *environment, commitedBundles []types.SimulatedBundle, usedSbundles []types.UsedSBundle) error {
	// bundleHash -> tx
	includedBundles := make(map[common.Hash][]bundleTxData)
	extractBundleTxDataFromBundles(commitedBundles, includedBundles)
	extractBundleTxDataFromSbundles(usedSbundles, includedBundles)
	includedTxDataByHash := extractIncludedTxDataFromEnv(env)

	return checkBundlesAtomicity(includedBundles, includedTxDataByHash)
}

type bundleTxData struct {
	hash      common.Hash
	canRevert bool
}

type includedTxData struct {
	hash     common.Hash
	index    int
	reverted bool
}

// checkBundlesAtomicity checks that all txs from the included bundles are included in the block correctly
// 1. We check that all non-reverted txs from the bundle are included in the block and are not reverted
// 2. Reverted txs are allowed to be not included in the block
// 3. All txs from the bundle must be in the right order, gaps between txs are allowed
func checkBundlesAtomicity(includedBundles map[common.Hash][]bundleTxData, includedTxDataByHash map[common.Hash]includedTxData) error {
	for bundleHash, b := range includedBundles {
		var (
			firstTxBlockIdx  int
			firstTxBundleIdx int
		)
		// 1. locate the first included tx of the bundle
		for bundleIdx, tx := range b {
			txInclusion, ok := includedTxDataByHash[tx.hash]
			if !ok {
				// tx not found, maybe it was reverting
				if tx.canRevert {
					continue
				} else {
					return NewErrBundleTxNotFound(bundleHash, tx.hash, bundleIdx)
				}
			}

			if txInclusion.reverted && !tx.canRevert {
				return NewErrBundleTxReverted(bundleHash, tx.hash, bundleIdx)
			}

			firstTxBlockIdx = txInclusion.index
			firstTxBundleIdx = bundleIdx
			break
		}

		currentBlockTx := firstTxBlockIdx + 1
		// locate other txs in the bundle
		for idx, tx := range b[firstTxBundleIdx+1:] {
			bundleIdx := firstTxBundleIdx + 1 + idx
			// see if tx is on its place
			txInclusion, ok := includedTxDataByHash[tx.hash]
			if !ok {
				// tx was not found, maybe its reverting
				if tx.canRevert {
					continue
				} else {
					return NewErrBundleTxNotFound(bundleHash, tx.hash, bundleIdx)
				}
			}

			// we allow gaps between txs in the bundle,
			// but txs must be in the right order
			if txInclusion.index < currentBlockTx {
				return NewErrBundleTxWrongPlace(bundleHash, tx.hash, bundleIdx, txInclusion.index, currentBlockTx)
			}

			if txInclusion.reverted && !tx.canRevert {
				return NewErrBundleTxReverted(bundleHash, tx.hash, bundleIdx)
			}

			currentBlockTx = txInclusion.index + 1
		}
	}
	return nil
}

func extractBundleTxDataFromBundles(bundles []types.SimulatedBundle, result map[common.Hash][]bundleTxData) {
	for _, b := range bundles {
		bundleData := make([]bundleTxData, len(b.OriginalBundle.Txs))
		for i, tx := range b.OriginalBundle.Txs {
			bundleData[i] = bundleTxData{
				hash:      tx.Hash(),
				canRevert: b.OriginalBundle.RevertingHash(tx.Hash()),
			}
		}
		result[b.OriginalBundle.Hash] = bundleData
	}
}

func getShareBundleTxData(bundle *types.SBundle) []bundleTxData {
	res := make([]bundleTxData, 0, len(bundle.Body))
	for _, el := range bundle.Body {
		if el.Tx != nil {
			res = append(res, bundleTxData{
				hash:      el.Tx.Hash(),
				canRevert: el.CanRevert,
			})
		} else if el.Bundle != nil {
			res = append(res, getShareBundleTxData(el.Bundle)...)
		}
	}
	return res
}

func extractBundleTxDataFromSbundles(bundles []types.UsedSBundle, result map[common.Hash][]bundleTxData) {
	for _, b := range bundles {
		if !b.Success {
			continue
		}
		result[b.Bundle.Hash()] = getShareBundleTxData(b.Bundle)
	}
}

func extractIncludedTxDataFromEnv(env *environment) map[common.Hash]includedTxData {
	res := make(map[common.Hash]includedTxData)
	for i, tx := range env.txs {
		if tx != nil {
			res[tx.Hash()] = includedTxData{
				hash:     tx.Hash(),
				index:    i,
				reverted: env.receipts[i].Status == types.ReceiptStatusFailed,
			}
		}
	}
	return res
}
