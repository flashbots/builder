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

// ErrPrivateTxFromFailedBundle is returned when a private tx is included in the block, but the bundle it belongs to was not included
type ErrPrivateTxFromFailedBundle struct {
	BundleHash common.Hash
	TxHash     common.Hash
	// Index of the tx in the bundle
	TxIndex int
}

func NewErrPrivateTxFromFailedBundle(bundleHash, txHash common.Hash, txIndex int) *ErrPrivateTxFromFailedBundle {
	return &ErrPrivateTxFromFailedBundle{
		BundleHash: bundleHash,
		TxHash:     txHash,
		TxIndex:    txIndex,
	}
}

func (e *ErrPrivateTxFromFailedBundle) Error() string {
	return fmt.Sprintf("private tx from failed bundle included in the block tx_hash=%s, bundle_hash=%s, tx_bundle_index=%d", e.TxHash.Hex(), e.BundleHash.Hex(), e.TxIndex)
}

// ErrUnexpectedTx is returned when a tx is included in the block, but it is not from the mempool or from the included bundles
type ErrUnexpectedTx struct {
	TxHash common.Hash
}

func NewErrUnexpectedTx(txHash common.Hash) *ErrUnexpectedTx {
	return &ErrUnexpectedTx{
		TxHash: txHash,
	}
}

func (e *ErrUnexpectedTx) Error() string {
	return fmt.Sprintf("unexpected tx included in the block tx_hash=%s", e.TxHash.Hex())
}

// VerifyBundlesAtomicity checks that all txs from the included bundles are included in the block correctly
// 1. We check that all non-reverted txs from the bundle are included in the block and are not reverted
// 2. Reverted txs are allowed to be not included in the block
// 3. All txs from the bundle must be in the right order, gaps between txs are allowed
// 4. All txs in the block are either from mempool or from the included bundles
func VerifyBundlesAtomicity(env *environment, committedBundles, allBundles []types.SimulatedBundle, usedSbundles []types.UsedSBundle, mempoolTxHashes map[common.Hash]struct{}) error {
	// bundleHash -> tx
	includedBundles := make(bundleHashToTransactionDataMap).
		ExtractFromBundles(committedBundles).
		ExtractFromSbundles(usedSbundles, true)

	includedTxDataByHash := extractIncludedTxDataFromEnv(env)

	allUsedBundles := make(bundleHashToTransactionDataMap).
		ExtractFromBundles(allBundles).
		ExtractFromSbundles(usedSbundles, false)

	privateTxDataFromFailedBundles := extractPrivateTxsFromFailedBundles(includedBundles, allUsedBundles, mempoolTxHashes)

	return checkBundlesAtomicity(includedBundles, includedTxDataByHash, privateTxDataFromFailedBundles, mempoolTxHashes)
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

type privateTxData struct {
	bundleHash common.Hash
	index      int
}

type bundleHashToTransactionDataMap map[common.Hash][]bundleTxData

func (btm bundleHashToTransactionDataMap) ExtractFromBundles(bundles []types.SimulatedBundle) bundleHashToTransactionDataMap {
	for _, b := range bundles {
		bundleData := make([]bundleTxData, len(b.OriginalBundle.Txs))
		for i, tx := range b.OriginalBundle.Txs {
			bundleData[i] = bundleTxData{
				hash:      tx.Hash(),
				canRevert: b.OriginalBundle.RevertingHash(tx.Hash()),
			}
		}

		btm[b.OriginalBundle.Hash] = bundleData
	}
	return btm
}

func (btm bundleHashToTransactionDataMap) ExtractFromSbundles(sbundles []types.UsedSBundle, onlyIncluded bool) bundleHashToTransactionDataMap {
	for _, b := range sbundles {
		if onlyIncluded && !b.Success {
			continue
		}
		btm[b.Bundle.Hash()] = getShareBundleTxData(b.Bundle)
	}
	return btm
}

// checkBundlesAtomicity checks that all txs from the included bundles are included in the block correctly
func checkBundlesAtomicity(
	includedBundles map[common.Hash][]bundleTxData,
	includedTxDataByHash map[common.Hash]includedTxData,
	privateTxsFromFailedBundles map[common.Hash]privateTxData,
	mempoolTxHashes map[common.Hash]struct{},
) error {
	txsFromSuccessfulBundles := make(map[common.Hash]struct{})

	for bundleHash, b := range includedBundles {
		var (
			firstTxBlockIdx  int
			firstTxBundleIdx int
			firstTxFound     = false
		)
		// 1. locate the first included tx of the bundle
		for bundleIdx, tx := range b {
			txsFromSuccessfulBundles[tx.hash] = struct{}{}

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

			// optional txs can be outside the bundle, so we don't use them to determine ordering of the bundle
			if tx.canRevert {
				continue
			}

			firstTxBlockIdx = txInclusion.index
			firstTxBundleIdx = bundleIdx
			firstTxFound = true
			break
		}

		// none of the txs from the bundle are included
		if !firstTxFound {
			continue
		}

		currentBlockTx := firstTxBlockIdx + 1
		// locate other txs in the bundle
		for idx, tx := range b[firstTxBundleIdx+1:] {
			txsFromSuccessfulBundles[tx.hash] = struct{}{}

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

			if txInclusion.reverted && !tx.canRevert {
				return NewErrBundleTxReverted(bundleHash, tx.hash, bundleIdx)
			}

			// we don't do position check for optional txs
			if tx.canRevert {
				continue
			}

			// we allow gaps between txs in the bundle,
			// but txs must be in the right order
			if txInclusion.index < currentBlockTx {
				return NewErrBundleTxWrongPlace(bundleHash, tx.hash, bundleIdx, txInclusion.index, currentBlockTx)
			}

			currentBlockTx = txInclusion.index + 1
		}
	}

	for hash, priv := range privateTxsFromFailedBundles {
		if _, ok := txsFromSuccessfulBundles[hash]; ok {
			continue
		}
		if _, ok := includedTxDataByHash[hash]; ok {
			return NewErrPrivateTxFromFailedBundle(priv.bundleHash, hash, priv.index)
		}
	}

	for hash := range includedTxDataByHash {
		if _, ok := txsFromSuccessfulBundles[hash]; ok {
			continue
		}
		if _, ok := mempoolTxHashes[hash]; ok {
			continue
		}
		return NewErrUnexpectedTx(hash)
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

func extractBundleTxDataFromSbundles(bundles []types.UsedSBundle, result map[common.Hash][]bundleTxData, onlyIncluded bool) {
	for _, b := range bundles {
		if onlyIncluded && !b.Success {
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

func extractPrivateTxsFromFailedBundles(
	includedBundles, allBundles map[common.Hash][]bundleTxData, mempoolTxHashes map[common.Hash]struct{},
) map[common.Hash]privateTxData {
	// we don't handle overlapping bundles here, they are handled in checkBundlesAtomicity
	res := make(map[common.Hash]privateTxData)

	for bundleHash, b := range allBundles {
		if _, bundleIncluded := includedBundles[bundleHash]; bundleIncluded {
			continue
		}

		for i, tx := range b {
			if _, mempool := mempoolTxHashes[tx.hash]; mempool {
				continue
			}
			res[tx.hash] = privateTxData{
				bundleHash: bundleHash,
				index:      i,
			}
		}
	}
	return res
}
