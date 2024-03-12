// Copyright 2023 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.
package txpool

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/event"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func pricedValuedTransaction(nonce uint64, value int64, gaslimit uint64, gasprice *big.Int, key *ecdsa.PrivateKey) *types.Transaction {
	tx, _ := types.SignTx(types.NewTransaction(nonce, common.Address{}, big.NewInt(value), gaslimit, gasprice, nil), types.HomesteadSigner{}, key)
	return tx
}

func count(t *testing.T, pool *TxPool) (pending int, queued int) {
	t.Helper()
	pending, queued = pool.stats()
	if err := validatePoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
	return pending, queued
}

func fillPool(t *testing.T, pool *TxPool) {
	t.Helper()
	// Create a number of test accounts, fund them and make transactions
	executableTxs := types.Transactions{}
	nonExecutableTxs := types.Transactions{}
	for i := 0; i < 384; i++ {
		key, _ := crypto.GenerateKey()
		pool.currentState.AddBalance(crypto.PubkeyToAddress(key.PublicKey), big.NewInt(10000000000))
		// Add executable ones
		for j := 0; j < int(pool.config.AccountSlots); j++ {
			executableTxs = append(executableTxs, pricedTransaction(uint64(j), 100000, big.NewInt(300), key))
		}
	}
	// Import the batch and verify that limits have been enforced
	pool.AddRemotesSync(executableTxs)
	pool.AddRemotesSync(nonExecutableTxs)
	pending, queued := pool.Stats()
	slots := pool.all.Slots()
	// sanity-check that the test prerequisites are ok (pending full)
	if have, want := pending, slots; have != want {
		t.Fatalf("have %d, want %d", have, want)
	}
	if have, want := queued, 0; have != want {
		t.Fatalf("have %d, want %d", have, want)
	}

	t.Logf("pool.config: GlobalSlots=%d, GlobalQueue=%d\n", pool.config.GlobalSlots, pool.config.GlobalQueue)
	t.Logf("pending: %d queued: %d, all: %d\n", pending, queued, slots)
}

// Tests that if a batch high-priced of non-executables arrive, they do not kick out
// executable transactions
func TestTransactionFutureAttack(t *testing.T) {
	t.Parallel()

	// Create the pool to test the limit enforcement with
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	blockchain := newTestBlockChain(1000000, statedb, new(event.Feed))
	config := testTxPoolConfig
	config.GlobalQueue = 100
	config.GlobalSlots = 100
	pool := NewTxPool(config, eip1559Config, blockchain)
	defer pool.Stop()
	fillPool(t, pool)
	pending, _ := pool.Stats()
	// Now, future transaction attack starts, let's add a bunch of expensive non-executables, and see if the pending-count drops
	{
		key, _ := crypto.GenerateKey()
		pool.currentState.AddBalance(crypto.PubkeyToAddress(key.PublicKey), big.NewInt(100000000000))
		futureTxs := types.Transactions{}
		for j := 0; j < int(pool.config.GlobalSlots+pool.config.GlobalQueue); j++ {
			futureTxs = append(futureTxs, pricedTransaction(1000+uint64(j), 100000, big.NewInt(500), key))
		}
		for i := 0; i < 5; i++ {
			pool.AddRemotesSync(futureTxs)
			newPending, newQueued := count(t, pool)
			t.Logf("pending: %d queued: %d, all: %d\n", newPending, newQueued, pool.all.Slots())
		}
	}
	newPending, _ := pool.Stats()
	// Pending should not have been touched
	if have, want := newPending, pending; have < want {
		t.Errorf("wrong pending-count, have %d, want %d (GlobalSlots: %d)",
			have, want, pool.config.GlobalSlots)
	}
}

// Tests that if a batch high-priced of non-executables arrive, they do not kick out
// executable transactions
func TestTransactionFuture1559(t *testing.T) {
	t.Parallel()
	// Create the pool to test the pricing enforcement with
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	blockchain := newTestBlockChain(1000000, statedb, new(event.Feed))
	pool := NewTxPool(testTxPoolConfig, eip1559Config, blockchain)
	defer pool.Stop()

	// Create a number of test accounts, fund them and make transactions
	fillPool(t, pool)
	pending, _ := pool.Stats()

	// Now, future transaction attack starts, let's add a bunch of expensive non-executables, and see if the pending-count drops
	{
		key, _ := crypto.GenerateKey()
		pool.currentState.AddBalance(crypto.PubkeyToAddress(key.PublicKey), big.NewInt(100000000000))
		futureTxs := types.Transactions{}
		for j := 0; j < int(pool.config.GlobalSlots+pool.config.GlobalQueue); j++ {
			futureTxs = append(futureTxs, dynamicFeeTx(1000+uint64(j), 100000, big.NewInt(200), big.NewInt(101), key))
		}
		pool.AddRemotesSync(futureTxs)
	}
	newPending, _ := pool.Stats()
	// Pending should not have been touched
	if have, want := newPending, pending; have != want {
		t.Errorf("Wrong pending-count, have %d, want %d (GlobalSlots: %d)",
			have, want, pool.config.GlobalSlots)
	}
}

// Tests that if a batch of balance-overdraft txs arrive, they do not kick out
// executable transactions
func TestTransactionZAttack(t *testing.T) {
	t.Parallel()
	// Create the pool to test the pricing enforcement with
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	blockchain := newTestBlockChain(1000000, statedb, new(event.Feed))
	pool := NewTxPool(testTxPoolConfig, eip1559Config, blockchain)
	defer pool.Stop()
	// Create a number of test accounts, fund them and make transactions
	fillPool(t, pool)

	countInvalidPending := func() int {
		t.Helper()
		var ivpendingNum int
		pendingtxs, _ := pool.Content()
		for account, txs := range pendingtxs {
			cur_balance := new(big.Int).Set(pool.currentState.GetBalance(account))
			for _, tx := range txs {
				if cur_balance.Cmp(tx.Value()) <= 0 {
					ivpendingNum++
				} else {
					cur_balance.Sub(cur_balance, tx.Value())
				}
			}
		}
		if err := validatePoolInternals(pool); err != nil {
			t.Fatalf("pool internal state corrupted: %v", err)
		}
		return ivpendingNum
	}
	ivPending := countInvalidPending()
	t.Logf("invalid pending: %d\n", ivPending)

	// Now, DETER-Z attack starts, let's add a bunch of expensive non-executables (from N accounts) along with balance-overdraft txs (from one account), and see if the pending-count drops
	for j := 0; j < int(pool.config.GlobalQueue); j++ {
		futureTxs := types.Transactions{}
		key, _ := crypto.GenerateKey()
		pool.currentState.AddBalance(crypto.PubkeyToAddress(key.PublicKey), big.NewInt(100000000000))
		futureTxs = append(futureTxs, pricedTransaction(1000+uint64(j), 21000, big.NewInt(500), key))
		pool.AddRemotesSync(futureTxs)
	}

	overDraftTxs := types.Transactions{}
	{
		key, _ := crypto.GenerateKey()
		pool.currentState.AddBalance(crypto.PubkeyToAddress(key.PublicKey), big.NewInt(100000000000))
		for j := 0; j < int(pool.config.GlobalSlots); j++ {
			overDraftTxs = append(overDraftTxs, pricedValuedTransaction(uint64(j), 60000000000, 21000, big.NewInt(500), key))
		}
	}
	pool.AddRemotesSync(overDraftTxs)
	pool.AddRemotesSync(overDraftTxs)
	pool.AddRemotesSync(overDraftTxs)
	pool.AddRemotesSync(overDraftTxs)
	pool.AddRemotesSync(overDraftTxs)

	newPending, newQueued := count(t, pool)
	newIvPending := countInvalidPending()
	t.Logf("pool.all.Slots(): %d\n", pool.all.Slots())
	t.Logf("pending: %d queued: %d, all: %d\n", newPending, newQueued, pool.all.Slots())
	t.Logf("invalid pending: %d\n", newIvPending)

	// Pending should not have been touched
	if newIvPending != ivPending {
		t.Errorf("Wrong invalid pending-count, have %d, want %d (GlobalSlots: %d, queued: %d)",
			newIvPending, ivPending, pool.config.GlobalSlots, newQueued)
	}
}

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
	fmt.Println(mbs)
}
