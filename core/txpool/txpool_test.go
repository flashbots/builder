package txpool

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// Tests that cancellable bundle prefers latest with the same bundle_uuid, but fallbacks to bundle_hash equality
func TestCancellableBundles(t *testing.T) {
	mb1 := types.MevBundle{
		Txs:               nil,
		BlockNumber:       big.NewInt(1),
		Uuid:              uuid.MustParse("2fa47a9c-1eb2-4189-b1b0-d79bf2d0fc83"),
		SigningAddress:    common.HexToAddress("0x1"),
		MinTimestamp:      0,
		MaxTimestamp:      0,
		RevertingTxHashes: []common.Hash{common.HexToHash("0x111")},
		Hash:              common.HexToHash("0x2"),
	}
	muid1 := mb1.ComputeUUID()

	mb2 := types.MevBundle{
		Txs:               nil,
		BlockNumber:       big.NewInt(1),
		Uuid:              uuid.MustParse("2fa47a9c-1eb2-4189-b1b0-d79bf2d0fc83"),
		SigningAddress:    common.HexToAddress("0x1"),
		MinTimestamp:      0,
		MaxTimestamp:      0,
		RevertingTxHashes: nil,
		Hash:              common.HexToHash("0x2"),
	}
	muid2 := mb2.ComputeUUID()
	_ = muid2

	mb3 := types.MevBundle{
		Txs:               nil,
		BlockNumber:       big.NewInt(1),
		Uuid:              uuid.MustParse("e2b1132f-7948-4227-aac4-041e9192110a"),
		SigningAddress:    common.HexToAddress("0x1"),
		MinTimestamp:      0,
		MaxTimestamp:      0,
		RevertingTxHashes: nil,
		Hash:              common.HexToHash("0x3"),
	}

	lubCh := make(chan []types.LatestUuidBundle, 1)
	errCh := make(chan error, 1)
	go func() {
		lub1 := types.LatestUuidBundle{
			Uuid:           uuid.MustParse("2fa47a9c-1eb2-4189-b1b0-d79bf2d0fc83"),
			SigningAddress: common.HexToAddress("0x1"),
			BundleHash:     common.HexToHash("0x2"),
			BundleUUID:     muid1,
		}
		lub2 := types.LatestUuidBundle{
			Uuid:           uuid.MustParse("e2b1132f-7948-4227-aac4-041e9192110a"),
			SigningAddress: common.HexToAddress("0x1"),
			BundleHash:     common.HexToHash("0x3"),
		}
		lubCh <- []types.LatestUuidBundle{lub1, lub2}
		errCh <- nil
	}()

	uuidBundles := make(map[uuidBundleKey][]types.MevBundle)
	firstUuidBK := uuidBundleKey{
		Uuid:           uuid.MustParse("2fa47a9c-1eb2-4189-b1b0-d79bf2d0fc83"),
		SigningAddress: common.HexToAddress("0x1"),
	}
	secondUuidBK := uuidBundleKey{
		Uuid:           uuid.MustParse("e2b1132f-7948-4227-aac4-041e9192110a"),
		SigningAddress: common.HexToAddress("0x1"),
	}

	uuidBundles[firstUuidBK] = []types.MevBundle{mb1, mb2}
	uuidBundles[secondUuidBK] = []types.MevBundle{mb3}

	mbs := resolveCancellableBundles(lubCh, errCh, uuidBundles)
	require.Equal(t, mbs[0], mb1)
	require.Equal(t, mbs[1], mb3)
}
