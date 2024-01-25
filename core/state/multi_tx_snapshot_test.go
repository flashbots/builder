package state

import (
	"bytes"
	"fmt"
	"math/rand"
	"reflect"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
)

var (
	addrs []common.Address
	keys  []common.Hash

	rng *rand.Rand
)

func init() {
	for i := 0; i < 20; i++ {
		addrs = append(addrs, common.HexToAddress(fmt.Sprintf("0x%02x", i)))
	}
	for i := 0; i < 100; i++ {
		keys = append(keys, common.HexToHash(fmt.Sprintf("0x%02x", i)))
	}
}

type observableAccountState struct {
	address  common.Address
	balance  *uint256.Int
	nonce    uint64
	code     []byte
	codeHash common.Hash
	codeSize int

	state          map[common.Hash]common.Hash
	committedState map[common.Hash]common.Hash

	selfDestruct bool
	exist        bool
	empty        bool
}

func getObservableAccountState(s *StateDB, address common.Address, storageKeys []common.Hash) *observableAccountState {
	state := &observableAccountState{
		address:        address,
		balance:        s.GetBalance(address),
		nonce:          s.GetNonce(address),
		code:           s.GetCode(address),
		codeHash:       s.GetCodeHash(address),
		codeSize:       s.GetCodeSize(address),
		state:          make(map[common.Hash]common.Hash),
		committedState: make(map[common.Hash]common.Hash),
		selfDestruct:   s.HasSelfDestructed(address),
		exist:          s.Exist(address),
		empty:          s.Empty(address),
	}

	for _, key := range storageKeys {
		state.state[key] = s.GetState(address, key)
		state.committedState[key] = s.GetCommittedState(address, key)
	}

	return state
}

func verifyObservableAccountState(s *StateDB, observed *observableAccountState) error {
	if s.GetBalance(observed.address).Cmp(observed.balance) != 0 {
		return fmt.Errorf("balance mismatch %v != %v", s.GetBalance(observed.address), observed.balance)
	}
	if s.GetNonce(observed.address) != observed.nonce {
		return fmt.Errorf("nonce mismatch %v != %v", s.GetNonce(observed.address), observed.nonce)
	}
	if !bytes.Equal(s.GetCode(observed.address), observed.code) {
		return fmt.Errorf("code mismatch %v != %v", s.GetCode(observed.address), observed.code)
	}
	if s.GetCodeHash(observed.address) != observed.codeHash {
		return fmt.Errorf("code hash mismatch %v != %v", s.GetCodeHash(observed.address), observed.codeHash)
	}
	if s.GetCodeSize(observed.address) != observed.codeSize {
		return fmt.Errorf("code size mismatch %v != %v", s.GetCodeSize(observed.address), observed.codeSize)
	}
	for key, value := range observed.state {
		found := s.GetState(observed.address, key)
		if found != value {
			return fmt.Errorf("state mismatch [key: %s] value %v != %v", key.String(), found, value)
		}
	}
	for key, value := range observed.committedState {
		found := s.GetCommittedState(observed.address, key)
		if found != value {
			return fmt.Errorf("committed state mismatch %v != %v", found, value)
		}
	}
	if s.HasSelfDestructed(observed.address) != observed.selfDestruct {
		return fmt.Errorf("self destruct mismatch %v != %v", s.HasSelfDestructed(observed.address), observed.selfDestruct)
	}
	if s.Exist(observed.address) != observed.exist {
		return fmt.Errorf("exist mismatch %v != %v", s.Exist(observed.address), observed.exist)
	}
	if s.Empty(observed.address) != observed.empty {
		return fmt.Errorf("empty mismatch %v != %v", s.Empty(observed.address), observed.empty)
	}
	return nil
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rng.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}

func randomHash() common.Hash {
	return common.BytesToHash(randomBytes(32))
}

func randFillAccountState(addr common.Address, s *StateDB) {
	for i, key := range keys {
		// Fill some keys with zero value, others with random value
		if i%5 == 0 {
			s.SetState(addr, key, common.BigToHash(common.Big0))
		} else {
			s.SetState(addr, key, randomHash())
		}
	}
}

func genRandomAccountState(seed int64) map[common.Address]map[common.Hash]common.Hash {
	rng = rand.New(rand.NewSource(seed))

	state := make(map[common.Address]map[common.Hash]common.Hash)

	for _, addr := range addrs {
		state[addr] = make(map[common.Hash]common.Hash)
		for i, key := range keys {
			if i%5 == 0 {
				state[addr][key] = common.BigToHash(common.Big0)
			} else {
				state[addr][key] = randomHash()
			}
		}
	}

	return state
}

func randFillAccount(addr common.Address, s *StateDB) {
	s.SetNonce(addr, rng.Uint64())
	s.SetBalance(addr, uint256.NewInt(rng.Uint64()))
	s.SetCode(addr, randomBytes(rng.Intn(100)))
	randFillAccountState(addr, s)
}

func prepareInitialState(s *StateDB) {
	// We neet to create realistic state for statedb
	// for this we apply some changes
	// 1. Before calling intermediateRoot
	// 2. After calling intermediateRoot but before calling Finalise
	rng = rand.New(rand.NewSource(0))

	var beforeCommitHooks, afterCommitHooks []func(addr common.Address, s *StateDB)
	addAccount := func(beforeCommit, afterCommit func(addr common.Address, s *StateDB)) {
		beforeCommitHooks = append(beforeCommitHooks, beforeCommit)
		afterCommitHooks = append(afterCommitHooks, afterCommit)
	}

	addAccount(func(addr common.Address, s *StateDB) {
		s.SetNonce(addr, rng.Uint64())
	}, nil)
	addAccount(nil, func(addr common.Address, s *StateDB) {
		s.SetNonce(addr, rng.Uint64())
	})
	addAccount(func(addr common.Address, s *StateDB) {
		s.SetNonce(addr, rng.Uint64())
	}, func(addr common.Address, s *StateDB) {
		s.SetNonce(addr, rng.Uint64())
	})

	addAccount(func(addr common.Address, s *StateDB) {
		s.SetBalance(addr, uint256.NewInt(rng.Uint64()))
	}, nil)
	addAccount(nil, func(addr common.Address, s *StateDB) {
		s.SetBalance(addr, uint256.NewInt(rng.Uint64()))
	})
	addAccount(func(addr common.Address, s *StateDB) {
		s.SetBalance(addr, uint256.NewInt(rng.Uint64()))
	}, func(addr common.Address, s *StateDB) {
		s.SetBalance(addr, uint256.NewInt(rng.Uint64()))
	})

	addAccount(func(addr common.Address, s *StateDB) {
		s.SetCode(addr, randomBytes(rng.Intn(100)))
	}, nil)
	addAccount(nil, func(addr common.Address, s *StateDB) {
		s.SetCode(addr, randomBytes(rng.Intn(100)))
	})
	addAccount(func(addr common.Address, s *StateDB) {
		s.SetCode(addr, randomBytes(rng.Intn(100)))
		s.SetCode(addr, nil)
	}, func(addr common.Address, s *StateDB) {
		s.SetCode(addr, randomBytes(rng.Intn(100)))
	})
	addAccount(func(addr common.Address, s *StateDB) {
		s.SetCode(addr, randomBytes(rng.Intn(100)))
		s.SelfDestruct(addr)
	}, func(addr common.Address, s *StateDB) {
		s.SetCode(addr, randomBytes(rng.Intn(100)))
	})

	addAccount(func(addr common.Address, s *StateDB) {
		randFillAccount(addr, s)
		s.SelfDestruct(addr)
	}, nil)
	addAccount(nil, func(addr common.Address, s *StateDB) {
		randFillAccount(addr, s)
		s.SelfDestruct(addr)
	})
	addAccount(func(addr common.Address, s *StateDB) {
		randFillAccount(addr, s)
	}, func(addr common.Address, s *StateDB) {
		s.SelfDestruct(addr)
	})
	addAccount(func(addr common.Address, s *StateDB) {
		randFillAccount(addr, s)
		s.SelfDestruct(addr)
	}, func(addr common.Address, s *StateDB) {
		randFillAccount(addr, s)
	})
	addAccount(func(addr common.Address, s *StateDB) {
		randFillAccount(addr, s)
		s.SelfDestruct(addr)
	}, func(addr common.Address, s *StateDB) {
		randFillAccount(addr, s)
		// calling it twice is possible
		s.SelfDestruct(addr)
		s.SelfDestruct(addr)
	})

	addAccount(func(addr common.Address, s *StateDB) {
		randFillAccount(addr, s)
	}, nil)
	addAccount(nil, func(addr common.Address, s *StateDB) {
		randFillAccount(addr, s)
	})

	for i, beforeHook := range beforeCommitHooks {
		if beforeHook != nil {
			beforeHook(addrs[i], s)
		}
	}
	s.IntermediateRoot(true)

	for i, afterHook := range afterCommitHooks {
		if afterHook != nil {
			afterHook(addrs[i], s)
		}
	}

	s.Finalise(true)
}

func testMultiTxSnapshot(t *testing.T, actions func(s *StateDB)) {
	s := newStateEnv()
	prepareInitialState(s.state)

	previousRefund := s.state.GetRefund()

	var obsStates []*observableAccountState
	for _, account := range addrs {
		obsStates = append(obsStates, getObservableAccountState(s.state, account, keys))
	}

	pendingAddressesBefore := make(map[common.Address]struct{})
	for k, v := range s.state.stateObjectsPending {
		pendingAddressesBefore[k] = v
	}
	dirtyAddressesBefore := make(map[common.Address]struct{})
	for k, v := range s.state.stateObjectsDirty {
		dirtyAddressesBefore[k] = v
	}

	err := s.state.NewMultiTxSnapshot()
	if err != nil {
		t.Fatal("MultiTxSnapshot failed", err)
	}

	if actions != nil {
		actions(s.state)
	}

	err = s.state.MultiTxSnapshotRevert()
	if err != nil {
		t.Fatal("MultiTxSnapshotRevert failed", err)
	}

	for _, obsState := range obsStates {
		err := verifyObservableAccountState(s.state, obsState)
		if err != nil {
			t.Error("state mismatch", "account", obsState.address, err)
		}
	}

	if s.state.GetRefund() != previousRefund {
		t.Error("refund mismatch", "got", s.state.GetRefund(), "expected", previousRefund)
	}

	if len(s.state.stateObjectsPending) != len(pendingAddressesBefore) {
		t.Error("pending state objects count mismatch", "got", len(s.state.stateObjectsPending), "expected", len(pendingAddressesBefore))
	}
	for k := range s.state.stateObjectsPending {
		if _, ok := pendingAddressesBefore[k]; !ok {
			t.Error("stateObjectsPending mismatch, before was nil", "address", k)
		}
	}
	if len(s.state.stateObjectsDirty) != len(dirtyAddressesBefore) {
		t.Error("dirty state objects count mismatch", "got", len(s.state.stateObjectsDirty), "expected", len(dirtyAddressesBefore))
	}
	for k := range s.state.stateObjectsDirty {
		if _, ok := dirtyAddressesBefore[k]; !ok {
			t.Error("stateObjectsDirty mismatch, before was nil", "address", k)
		}
	}

	root := s.state.IntermediateRoot(true)

	cleanState := newStateEnv()
	prepareInitialState(cleanState.state)
	expectedRoot := cleanState.state.IntermediateRoot(true)

	if root != expectedRoot {
		t.Error("root mismatch", "got", root, "expected", expectedRoot)
	}
}

func TestMultiTxSnapshotAccountChangesSimple(t *testing.T) {
	testMultiTxSnapshot(t, func(s *StateDB) {
		for _, addr := range addrs {
			s.SetNonce(addr, 78)
			s.SetBalance(addr, uint256.NewInt(79))
			s.SetCode(addr, []byte{0x80})
		}
		s.Finalise(true)
	})
}

// This test verifies that dirty account storage is properly cleaned for accounts after revert
func TestMultiTxSnapshotAccountChangesRevertedByJournal(t *testing.T) {
	testMultiTxSnapshot(t, func(s *StateDB) {
		for _, addr := range addrs {
			s.SetState(addr, common.HexToHash("0x01"), common.HexToHash("0x03"))
		}
		s.Finalise(true)
		for _, addr := range addrs {
			// we use normal snapshot here because it
			// 1. does not mark an account dirty (even though we applied changes)
			// 2. changes dirty, uncommitted state of the account
			snap := s.Snapshot()
			s.SetState(addr, common.HexToHash("0x01"), common.HexToHash("0x02"))
			s.RevertToSnapshot(snap)
		}
		s.Finalise(true)
	})
}

func TestMultiTxSnapshotRefund(t *testing.T) {
	testMultiTxSnapshot(t, func(s *StateDB) {
		for _, addr := range addrs {
			s.SetNonce(addr, 78)
			s.SetBalance(addr, uint256.NewInt(79))
			s.SetCode(addr, []byte{0x80})
		}
		s.Finalise(true)
	})
}

func TestMultiTxSnapshotAccountChangesMultiTx(t *testing.T) {
	testMultiTxSnapshot(t, func(s *StateDB) {
		for _, addr := range addrs {
			s.SetNonce(addr, 78)
			s.SetBalance(addr, uint256.NewInt(79))
			s.SetCode(addr, []byte{0x80})
		}
		s.Finalise(true)

		for _, addr := range addrs {
			s.SetNonce(addr, 79)
			s.SetBalance(addr, uint256.NewInt(80))
			s.SetCode(addr, []byte{0x81})
		}
		s.Finalise(true)
	})
}

func TestMultiTxSnapshotAccountChangesSelfDestruct(t *testing.T) {
	testMultiTxSnapshot(t, func(s *StateDB) {
		for _, addr := range addrs {
			s.SetNonce(addr, 78)
			s.SetBalance(addr, uint256.NewInt(79))
			s.SetCode(addr, []byte{0x80})
		}
		s.Finalise(true)

		for _, addr := range addrs {
			s.SelfDestruct(addr)
		}
		s.Finalise(true)

		for _, addr := range addrs {
			s.SetNonce(addr, 79)
			s.SetBalance(addr, uint256.NewInt(80))
			s.SetCode(addr, []byte{0x81})
		}
		s.Finalise(true)
	})
}

func TestMultiTxSnapshotAccountChangesEmptyAccount(t *testing.T) {
	testMultiTxSnapshot(t, func(s *StateDB) {
		for _, addr := range addrs {
			s.SetNonce(addr, 78)
			s.SetBalance(addr, uint256.NewInt(79))
			s.SetCode(addr, []byte{0x80})
		}
		s.Finalise(true)

		for _, addr := range addrs {
			s.SetNonce(addr, 0)
			s.SetBalance(addr, common.U2560)
			s.SetCode(addr, nil)
		}
		s.Finalise(true)

		for _, addr := range addrs {
			s.SetNonce(addr, 79)
			s.SetBalance(addr, uint256.NewInt(80))
			s.SetCode(addr, []byte{0x81})
		}
		s.Finalise(true)
	})
}

func TestMultiTxSnapshotStateChanges(t *testing.T) {
	testMultiTxSnapshot(t, func(s *StateDB) {
		for _, addr := range addrs {
			randFillAccountState(addr, s)
		}
		s.Finalise(true)

		for _, addr := range addrs {
			randFillAccountState(addr, s)
		}
		s.Finalise(true)
	})
}

func TestStackBasic(t *testing.T) {
	for i := 0; i < 10; i++ {
		testMultiTxSnapshot(t, func(s *StateDB) {
			// when test starts, actions are performed after new snapshot is created
			// we initialize additional snapshot on top of that
			if err := s.NewMultiTxSnapshot(); err != nil {
				t.Errorf("NewMultiTxSnapshot failed: %v", err)
				t.FailNow()
			}

			seed := rand.Int63()
			stateMap := genRandomAccountState(seed)
			for account, accountKeys := range stateMap {
				for key, value := range accountKeys {
					s.SetState(account, key, value)
				}
			}
			s.Finalise(true)

			stack := s.multiTxSnapshotStack

			// the test starts with 1 snapshot, and we just created new one above
			startSize := stack.Size()
			if startSize != 2 {
				t.Errorf("expected stack size to be 2, got %d", startSize)
				t.FailNow()
			}

			for _, addr := range addrs {
				if err := s.NewMultiTxSnapshot(); err != nil {
					t.Errorf("NewMultiTxSnapshot failed: %v", err)
					t.FailNow()
				}
				randFillAccountState(addr, s)
				s.Finalise(true)
			}
			afterAddrSize := stack.Size()
			if afterAddrSize != startSize+len(addrs) {
				t.Errorf("expected stack size to be %d, got %d", startSize+len(addrs), afterAddrSize)
				t.FailNow()
			}

			// the testMultiTxSnapshot subroutine calls MultiTxSnapshotRevert after applying actions
			// we test here to make sure that the flattened commitments on the head of stack
			// yield the same final root hash
			// this ensures that we are properly flattening the stack on commit
			for stack.Size() > 1 {
				if _, err := stack.Commit(); err != nil {
					t.Errorf("Commit failed: %v", err)
					t.FailNow()
				}
			}
		})
	}
}

func TestStackSelfDestruct(t *testing.T) {
	testMultiTxSnapshot(t, func(s *StateDB) {
		if err := s.NewMultiTxSnapshot(); err != nil {
			t.Errorf("NewMultiTxSnapshot failed: %v", err)
			t.FailNow()
		}
		for _, addr := range addrs {
			s.SetNonce(addr, 78)
			s.SetBalance(addr, uint256.NewInt(79))
			s.SetCode(addr, []byte{0x80})
			s.Finalise(true)
		}

		for _, addr := range addrs {
			if err := s.NewMultiTxSnapshot(); err != nil {
				t.Errorf("NewMultiTxSnapshot failed: %v", err)
				t.FailNow()
			}
			s.SelfDestruct(addr)
		}
		stack := s.multiTxSnapshotStack

		// merge all the suicide operations
		for stack.Size() > 1 {
			if _, err := stack.Commit(); err != nil {
				t.Errorf("Commit failed: %v", err)
				t.FailNow()
			}
		}
		s.Finalise(true)

		for _, addr := range addrs {
			s.SetNonce(addr, 79)
			s.SetBalance(addr, uint256.NewInt(80))
			s.SetCode(addr, []byte{0x81})
		}
		s.Finalise(true)
	})
}

func TestStackAgainstSingleSnap(t *testing.T) {
	// we generate a random seed ten times to fuzz test multiple stack snapshots against single layer snapshot
	for i := 0; i < 10; i++ {
		testMultiTxSnapshot(t, func(s *StateDB) {
			// Need to drop initial snapshot since copy requires empty snapshot stack
			if err := s.MultiTxSnapshotRevert(); err != nil {
				t.Fatalf("error reverting snapshot: %v", err)
			}
			original := s.Copy()
			baselineStateDB := s.Copy()

			baselineRootHash, targetRootHash := baselineStateDB.originalRoot, s.originalRoot

			if !bytes.Equal(baselineRootHash.Bytes(), targetRootHash.Bytes()) {
				t.Errorf("expected root hash to be %x, got %x", baselineRootHash, targetRootHash)
				t.FailNow()
			}

			// basic - add multiple snapshots and commit them, and compare them to single snapshot that has all
			// state changes

			if err := baselineStateDB.NewMultiTxSnapshot(); err != nil {
				t.Errorf("Error initializing snapshot: %v", err)
				t.FailNow()
			}

			if err := s.NewMultiTxSnapshot(); err != nil {
				t.Errorf("Error initializing snapshot: %v", err)
				t.FailNow()
			}

			// we should be able to revert back to the same intermediate root hash
			// for single snapshot and snapshot stack
			seed := rand.Int63()
			state := genRandomAccountState(seed)
			for account, accountKeys := range state {
				for key, value := range accountKeys {
					baselineStateDB.SetState(account, key, value)

					if err := s.NewMultiTxSnapshot(); err != nil {
						t.Errorf("Error initializing snapshot: %v", err)
						t.FailNow()
					}
					s.SetState(account, key, value)
					s.Finalise(true)
				}
			}
			baselineStateDB.Finalise(true)

			// commit all but last snapshot
			stack := s.multiTxSnapshotStack
			for stack.Size() > 1 {
				if _, err := stack.Commit(); err != nil {
					t.Errorf("Commit failed: %v", err)
					t.FailNow()
				}
			}

			var (
				baselineSnapshot = baselineStateDB.multiTxSnapshotStack.Peek()
				targetSnapshot   = s.multiTxSnapshotStack.Peek()
			)
			if !targetSnapshot.Equal(baselineSnapshot) {
				CompareAndPrintSnapshotMismatches(t, targetSnapshot, baselineSnapshot)
				t.Errorf("expected snapshots to be equal")
				t.FailNow()
			}

			// revert back to previously calculated root hash
			if err := baselineStateDB.MultiTxSnapshotRevert(); err != nil {
				t.Errorf("MultiTxSnapshotRevert failed: %v", err)
				t.FailNow()
			}

			if err := s.MultiTxSnapshotRevert(); err != nil {
				t.Errorf("MultiTxSnapshotRevert failed: %v", err)
				t.FailNow()
			}

			var err error
			if targetRootHash, err = s.Commit(0, true); err != nil {
				t.Errorf("Commit failed: %v", err)
				t.FailNow()
			}

			if baselineRootHash, err = baselineStateDB.Commit(0, true); err != nil {
				t.Errorf("Commit failed: %v", err)
				t.FailNow()
			}
			if !bytes.Equal(baselineRootHash.Bytes(), targetRootHash.Bytes()) {
				t.Errorf("expected root hash to be %x, got %x", baselineRootHash, targetRootHash)
				t.FailNow()
			}

			*s = *original
			if err := s.NewMultiTxSnapshot(); err != nil {
				t.Errorf("Error initializing snapshot: %v", err)
				t.FailNow()
			}
		})
	}
}

func CompareAndPrintSnapshotMismatches(t *testing.T, target, other *MultiTxSnapshot) {
	var out bytes.Buffer
	if target.Equal(other) {
		t.Logf("Snapshots are equal")
		return
	}

	if target.invalid != other.invalid {
		out.WriteString(fmt.Sprintf("invalid: %v != %v\n", target.invalid, other.invalid))
		return
	}

	// check log mismatch
	visited := make(map[common.Hash]bool)
	for address, logCount := range other.numLogsAdded {
		targetLogCount, exists := target.numLogsAdded[address]
		if !exists {
			out.WriteString(fmt.Sprintf("target<>other numLogsAdded[missing]: %v\n", address))
			continue
		}
		if targetLogCount != logCount {
			out.WriteString(fmt.Sprintf("target<>other numLogsAdded[%x]: %v != %v\n", address, targetLogCount, logCount))
		}
	}

	for address, logCount := range target.numLogsAdded {
		if visited[address] {
			continue
		}

		otherLogCount, exists := other.numLogsAdded[address]
		if !exists {
			out.WriteString(fmt.Sprintf("other<>target numLogsAdded[missing]: %v\n", address))
			continue
		}

		if otherLogCount != logCount {
			out.WriteString(fmt.Sprintf("other<>target numLogsAdded[%x]: %v != %v\n", address, otherLogCount, logCount))
		}
	}

	// check previous objects mismatch
	for address := range other.prevObjects {
		// TODO: we only check existence, need to add RLP comparison
		_, exists := target.prevObjects[address]
		if !exists {
			out.WriteString(fmt.Sprintf("target<>other prevObjects[missing]: %v\n", address.String()))
			continue
		}
	}

	for address, obj := range target.prevObjects {
		otherObj, exists := other.prevObjects[address]
		if !exists {
			out.WriteString(fmt.Sprintf("other<>target prevObjects[missing]: %v\n", address))
			continue
		}
		if !reflect.DeepEqual(otherObj, obj) {
			out.WriteString(fmt.Sprintf("other<>target prevObjects[%x]: %v != %v\n", address, otherObj, obj))
		}
	}

	// check account storage mismatch
	for account, storage := range other.accountStorage {
		targetStorage, exists := target.accountStorage[account]
		if !exists {
			out.WriteString(fmt.Sprintf("target<>other accountStorage[missing]: %v\n", account))
			continue
		}

		for key, value := range storage {
			targetValue, exists := targetStorage[key]
			if !exists {
				out.WriteString(fmt.Sprintf("target<>other accountStorage[%s][missing]: %v\n", account.String(), key.String()))
				continue
			}
			if !reflect.DeepEqual(targetValue, value) {
				out.WriteString(fmt.Sprintf("target<>other accountStorage[%s][%s]: %v != %v\n", account.String(), key.String(), targetValue.String(), value.String()))
			}
		}
	}

	for account, storage := range target.accountStorage {
		otherStorage, exists := other.accountStorage[account]
		if !exists {
			out.WriteString(fmt.Sprintf("other<>target accountStorage[missing]: %v\n", account))
			continue
		}

		for key, value := range storage {
			otherValue, exists := otherStorage[key]
			if !exists {
				out.WriteString(fmt.Sprintf("other<>target accountStorage[%s][missing]: %v\n", account.String(), key.String()))
				continue
			}
			if !reflect.DeepEqual(otherValue, value) {
				out.WriteString(fmt.Sprintf("other<>target accountStorage[%s][%s]: %v != %v\n", account.String(), key.String(), otherValue.String(), value.String()))
			}
		}
	}

	// check account balance mismatch
	for account, balance := range other.accountBalance {
		targetBalance, exists := target.accountBalance[account]
		if !exists {
			out.WriteString(fmt.Sprintf("target<>other accountBalance[missing]: %v\n", account))
			continue
		}
		if !reflect.DeepEqual(targetBalance, balance) {
			out.WriteString(fmt.Sprintf("target<>other accountBalance[%x]: %v != %v\n", account, targetBalance, balance))
		}
	}

	for account, balance := range target.accountBalance {
		otherBalance, exists := other.accountBalance[account]
		if !exists {
			out.WriteString(fmt.Sprintf("other<>target accountBalance[missing]: %v\n", account))
			continue
		}
		if !bytes.Equal(otherBalance.Bytes(), balance.Bytes()) {
			out.WriteString(fmt.Sprintf("other<>target accountBalance[%x]: %v != %v\n", account, otherBalance, balance))
		}
	}

	// check account nonce mismatch
	for account, nonce := range other.accountNonce {
		targetNonce, exists := target.accountNonce[account]
		if !exists {
			out.WriteString(fmt.Sprintf("target<>other accountNonce[missing]: %v\n", account))
			continue
		}
		if targetNonce != nonce {
			out.WriteString(fmt.Sprintf("target<>other accountNonce[%x]: %v != %v\n", account, targetNonce, nonce))
		}
	}

	for account, nonce := range target.accountNonce {
		otherNonce, exists := other.accountNonce[account]
		if !exists {
			out.WriteString(fmt.Sprintf("other<>target accountNonce[missing]: %v\n", account))
			continue
		}
		if otherNonce != nonce {
			out.WriteString(fmt.Sprintf("other<>target accountNonce[%x]: %v != %v\n", account, otherNonce, nonce))
		}
	}

	// check account code mismatch
	for account, code := range other.accountCode {
		targetCode, exists := target.accountCode[account]
		if !exists {
			out.WriteString(fmt.Sprintf("target<>other accountCode[missing]: %v\n", account))
			continue
		}
		if !bytes.Equal(targetCode, code) {
			out.WriteString(fmt.Sprintf("target<>other accountCode[%x]: %v != %v\n", account, targetCode, code))
		}
	}

	for account, code := range target.accountCode {
		otherCode, exists := other.accountCode[account]
		if !exists {
			out.WriteString(fmt.Sprintf("other<>target accountCode[missing]: %v\n", account))
			continue
		}
		if !bytes.Equal(otherCode, code) {
			out.WriteString(fmt.Sprintf("other<>target accountCode[%x]: %v != %v\n", account, otherCode, code))
		}
	}

	// check account codeHash mismatch
	for account, codeHash := range other.accountCodeHash {
		targetCodeHash, exists := target.accountCodeHash[account]
		if !exists {
			out.WriteString(fmt.Sprintf("target<>other accountCodeHash[missing]: %v\n", account))
			continue
		}
		if !bytes.Equal(targetCodeHash, codeHash) {
			out.WriteString(fmt.Sprintf("target<>other accountCodeHash[%x]: %v != %v\n", account, targetCodeHash, codeHash))
		}
	}

	for account, codeHash := range target.accountCodeHash {
		otherCodeHash, exists := other.accountCodeHash[account]
		if !exists {
			out.WriteString(fmt.Sprintf("other<>target accountCodeHash[missing]: %v\n", account))
			continue
		}
		if !bytes.Equal(otherCodeHash, codeHash) {
			out.WriteString(fmt.Sprintf("other<>target accountCodeHash[%x]: %v != %v\n", account, otherCodeHash, codeHash))
		}
	}

	// check account suicide mismatch
	for account, suicide := range other.accountSelfDestruct {
		targetSuicide, exists := target.accountSelfDestruct[account]
		if !exists {
			out.WriteString(fmt.Sprintf("target<>other accountSuicided[missing]: %v\n", account))
			continue
		}

		if targetSuicide != suicide {
			out.WriteString(fmt.Sprintf("target<>other accountSuicided[%x]: %t != %t\n", account, targetSuicide, suicide))
		}
	}

	for account, suicide := range target.accountSelfDestruct {
		otherSuicide, exists := other.accountSelfDestruct[account]
		if !exists {
			out.WriteString(fmt.Sprintf("other<>target accountSuicided[missing]: %v\n", account))
			continue
		}

		if otherSuicide != suicide {
			out.WriteString(fmt.Sprintf("other<>target accountSuicided[%x]: %t != %t\n", account, otherSuicide, suicide))
		}
	}

	// check account deletion mismatch
	for account, del := range other.accountDeleted {
		targetDelete, exists := target.accountDeleted[account]
		if !exists {
			out.WriteString(fmt.Sprintf("target<>other accountDeleted[missing]: %v\n", account))
			continue
		}

		if targetDelete != del {
			out.WriteString(fmt.Sprintf("target<>other accountDeleted[%x]: %v != %v\n", account, targetDelete, del))
		}
	}

	for account, del := range target.accountDeleted {
		otherDelete, exists := other.accountDeleted[account]
		if !exists {
			out.WriteString(fmt.Sprintf("other<>target accountDeleted[missing]: %v\n", account))
			continue
		}

		if otherDelete != del {
			out.WriteString(fmt.Sprintf("other<>target accountDeleted[%x]: %v != %v\n", account, otherDelete, del))
		}
	}

	// check account not pending mismatch
	for account := range other.accountNotPending {
		if _, exists := target.accountNotPending[account]; !exists {
			out.WriteString(fmt.Sprintf("target<>other accountNotPending[missing]: %v\n", account))
		}
	}

	for account := range target.accountNotPending {
		if _, exists := other.accountNotPending[account]; !exists {
			out.WriteString(fmt.Sprintf("other<>target accountNotPending[missing]: %v\n", account))
		}
	}

	// check account not dirty mismatch
	for account := range other.accountNotDirty {
		if _, exists := target.accountNotDirty[account]; !exists {
			out.WriteString(fmt.Sprintf("target<>other accountNotDirty[missing]: %v\n", account))
		}
	}

	for account := range target.accountNotDirty {
		if _, exists := other.accountNotDirty[account]; !exists {
			out.WriteString(fmt.Sprintf("other<>target accountNotDirty[missing]: %v\n", account))
		}
	}

	fmt.Println(out.String())
	out.Reset()
}
