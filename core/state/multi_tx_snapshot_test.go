package state

import (
	"bytes"
	"fmt"
	"math/big"
	"math/rand"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

var (
	addrs []common.Address
	keys  []common.Hash

	rng *rand.Rand
)

func init() {
	rng = rand.New(rand.NewSource(0))

	for i := 0; i < 20; i++ {
		addrs = append(addrs, common.HexToAddress(fmt.Sprintf("0x%02x", i)))
	}
	for i := 0; i < 10; i++ {
		keys = append(keys, common.HexToHash(fmt.Sprintf("0x%02x", i)))
	}
}

type observableAccountState struct {
	address  common.Address
	balance  *big.Int
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
		selfDestruct:   s.HasSuicided(address),
		exist:          s.Exist(address),
		empty:          s.Empty(address),
	}

	for _, key := range storageKeys {
		state.state[key] = s.GetState(address, key)
		state.committedState[key] = s.GetCommittedState(address, key)
	}

	return state
}

func verifyObservableAccountState(s *StateDB, state *observableAccountState) error {
	if s.GetBalance(state.address).Cmp(state.balance) != 0 {
		return fmt.Errorf("balance mismatch %v != %v", s.GetBalance(state.address), state.balance)
	}
	if s.GetNonce(state.address) != state.nonce {
		return fmt.Errorf("nonce mismatch %v != %v", s.GetNonce(state.address), state.nonce)
	}
	if !bytes.Equal(s.GetCode(state.address), state.code) {
		return fmt.Errorf("code mismatch %v != %v", s.GetCode(state.address), state.code)
	}
	if s.GetCodeHash(state.address) != state.codeHash {
		return fmt.Errorf("code hash mismatch %v != %v", s.GetCodeHash(state.address), state.codeHash)
	}
	if s.GetCodeSize(state.address) != state.codeSize {
		return fmt.Errorf("code size mismatch %v != %v", s.GetCodeSize(state.address), state.codeSize)
	}
	for key, value := range state.state {
		if s.GetState(state.address, key) != value {
			return fmt.Errorf("state mismatch %v != %v", s.GetState(state.address, key), value)
		}
	}
	for key, value := range state.committedState {
		if s.GetCommittedState(state.address, key) != value {
			return fmt.Errorf("committed state mismatch %v != %v", s.GetCommittedState(state.address, key), value)
		}
	}
	if s.HasSuicided(state.address) != state.selfDestruct {
		return fmt.Errorf("self destruct mismatch %v != %v", s.HasSuicided(state.address), state.selfDestruct)
	}
	if s.Exist(state.address) != state.exist {
		return fmt.Errorf("exist mismatch %v != %v", s.Exist(state.address), state.exist)
	}
	if s.Empty(state.address) != state.empty {
		return fmt.Errorf("empty mismatch %v != %v", s.Empty(state.address), state.empty)
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

func randFillAccount(addr common.Address, s *StateDB) {
	s.SetNonce(addr, rng.Uint64())
	s.SetBalance(addr, big.NewInt(rng.Int63()))
	s.SetCode(addr, randomBytes(rng.Intn(100)))
	randFillAccountState(addr, s)
}

func prepareInitialState(s *StateDB) {
	// We neet to create realistic state for statedb
	// for this we apply some changes
	// 1. Before calling intermediateRoot
	// 2. After calling intermediateRoot but before calling Finalise
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
		s.SetBalance(addr, big.NewInt(rng.Int63()))
	}, nil)
	addAccount(nil, func(addr common.Address, s *StateDB) {
		s.SetBalance(addr, big.NewInt(rng.Int63()))
	})
	addAccount(func(addr common.Address, s *StateDB) {
		s.SetBalance(addr, big.NewInt(rng.Int63()))
	}, func(addr common.Address, s *StateDB) {
		s.SetBalance(addr, big.NewInt(rng.Int63()))
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
		s.Suicide(addr)
	}, func(addr common.Address, s *StateDB) {
		s.SetCode(addr, randomBytes(rng.Intn(100)))
	})

	addAccount(func(addr common.Address, s *StateDB) {
		randFillAccount(addr, s)
		s.Suicide(addr)
	}, nil)
	addAccount(nil, func(addr common.Address, s *StateDB) {
		randFillAccount(addr, s)
		s.Suicide(addr)
	})
	addAccount(func(addr common.Address, s *StateDB) {
		randFillAccount(addr, s)
	}, func(addr common.Address, s *StateDB) {
		s.Suicide(addr)
	})
	addAccount(func(addr common.Address, s *StateDB) {
		randFillAccount(addr, s)
		s.Suicide(addr)
	}, func(addr common.Address, s *StateDB) {
		randFillAccount(addr, s)
	})
	addAccount(func(addr common.Address, s *StateDB) {
		randFillAccount(addr, s)
		s.Suicide(addr)
	}, func(addr common.Address, s *StateDB) {
		randFillAccount(addr, s)
		// calling it twice is possible
		s.Suicide(addr)
		s.Suicide(addr)
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

func testMutliTxSnapshot(t *testing.T, actions func(s *StateDB)) {
	s := newStateTest()
	prepareInitialState(s.state)

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

	err := s.state.MultiTxSnapshot()
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

	cleanState := newStateTest()
	prepareInitialState(cleanState.state)
	expectedRoot := cleanState.state.IntermediateRoot(true)

	if root != expectedRoot {
		t.Error("root mismatch", "got", root, "expected", expectedRoot)
	}
}

func TestMultiTxSnapshotAccountChangesSimple(t *testing.T) {
	testMutliTxSnapshot(t, func(s *StateDB) {
		for _, addr := range addrs {
			s.SetNonce(addr, 78)
			s.SetBalance(addr, big.NewInt(79))
			s.SetCode(addr, []byte{0x80})
		}
		s.Finalise(true)
	})
}

func TestMultiTxSnapshotAccountChangesMultiTx(t *testing.T) {
	testMutliTxSnapshot(t, func(s *StateDB) {
		for _, addr := range addrs {
			s.SetNonce(addr, 78)
			s.SetBalance(addr, big.NewInt(79))
			s.SetCode(addr, []byte{0x80})
		}
		s.Finalise(true)

		for _, addr := range addrs {
			s.SetNonce(addr, 79)
			s.SetBalance(addr, big.NewInt(80))
			s.SetCode(addr, []byte{0x81})
		}
		s.Finalise(true)
	})
}

func TestMultiTxSnapshotAccountChangesSelfDestruct(t *testing.T) {
	testMutliTxSnapshot(t, func(s *StateDB) {
		for _, addr := range addrs {
			s.SetNonce(addr, 78)
			s.SetBalance(addr, big.NewInt(79))
			s.SetCode(addr, []byte{0x80})
		}
		s.Finalise(true)

		for _, addr := range addrs {
			s.Suicide(addr)
		}
		s.Finalise(true)

		for _, addr := range addrs {
			s.SetNonce(addr, 79)
			s.SetBalance(addr, big.NewInt(80))
			s.SetCode(addr, []byte{0x81})
		}
		s.Finalise(true)
	})
}

func TestMultiTxSnapshotAccountChangesEmptyAccount(t *testing.T) {
	testMutliTxSnapshot(t, func(s *StateDB) {
		for _, addr := range addrs {
			s.SetNonce(addr, 78)
			s.SetBalance(addr, big.NewInt(79))
			s.SetCode(addr, []byte{0x80})
		}
		s.Finalise(true)

		for _, addr := range addrs {
			s.SetNonce(addr, 0)
			s.SetBalance(addr, common.Big0)
			s.SetCode(addr, nil)
		}
		s.Finalise(true)

		for _, addr := range addrs {
			s.SetNonce(addr, 79)
			s.SetBalance(addr, big.NewInt(80))
			s.SetCode(addr, []byte{0x81})
		}
		s.Finalise(true)
	})
}

func TestMultiTxSnapshotStateChanges(t *testing.T) {
	testMutliTxSnapshot(t, func(s *StateDB) {
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
