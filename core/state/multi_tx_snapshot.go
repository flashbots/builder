package state

import (
	"github.com/ethereum/go-ethereum/common"
	"math/big"
)

// MultiTxSnapshot retains StateDB changes for multiple transactions.
type MultiTxSnapshot struct {
	invalid bool

	numLogsAdded map[common.Hash]int

	prevObjects map[common.Address]*stateObject

	accountStorage  map[common.Address]map[common.Hash]*common.Hash
	accountBalance  map[common.Address]*big.Int
	accountNonce    map[common.Address]uint64
	accountCode     map[common.Address][]byte
	accountCodeHash map[common.Address][]byte

	accountSuicided map[common.Address]bool
	accountDeleted  map[common.Address]bool

	accountNotPending map[common.Address]struct{}
	accountNotDirty   map[common.Address]struct{}
}

func NewMultiTxSnapshot() *MultiTxSnapshot {
	return &MultiTxSnapshot{
		numLogsAdded:      make(map[common.Hash]int),
		prevObjects:       make(map[common.Address]*stateObject),
		accountStorage:    make(map[common.Address]map[common.Hash]*common.Hash),
		accountBalance:    make(map[common.Address]*big.Int),
		accountNonce:      make(map[common.Address]uint64),
		accountCode:       make(map[common.Address][]byte),
		accountCodeHash:   make(map[common.Address][]byte),
		accountSuicided:   make(map[common.Address]bool),
		accountDeleted:    make(map[common.Address]bool),
		accountNotPending: make(map[common.Address]struct{}),
		accountNotDirty:   make(map[common.Address]struct{}),
	}
}

// updateFromJournal updates the snapshot with the changes from the journal.
func (s *MultiTxSnapshot) updateFromJournal(journal *journal) {
	for _, journalEntry := range journal.entries {
		switch entry := journalEntry.(type) {
		case balanceChange:
			s.updateBalanceChange(entry)
		case nonceChange:
			s.updateNonceChange(entry)
		case codeChange:
			s.updateCodeChange(entry)
		case addLogChange:
			s.numLogsAdded[entry.txhash]++
		case createObjectChange:
			s.updateCreateObjectChange(entry)
		case resetObjectChange:
			s.updateResetObjectChange(entry)
		case suicideChange:
			s.updateSuicideChange(entry)
		}
	}
}

// objectChanged returns whether the object was changed (in the set of prevObjects).
func (s *MultiTxSnapshot) objectChanged(address common.Address) bool {
	_, ok := s.prevObjects[address]
	return ok
}

// updateBalanceChange updates the snapshot with the balance change.
func (s *MultiTxSnapshot) updateBalanceChange(change balanceChange) {
	if s.objectChanged(*change.account) {
		return
	}
	if _, ok := s.accountBalance[*change.account]; !ok {
		s.accountBalance[*change.account] = change.prev
	}
}

// updateNonceChange updates the snapshot with the nonce change.
func (s *MultiTxSnapshot) updateNonceChange(change nonceChange) {
	if s.objectChanged(*change.account) {
		return
	}
	if _, ok := s.accountNonce[*change.account]; !ok {
		s.accountNonce[*change.account] = change.prev
	}
}

// updateCodeChange updates the snapshot with the code change.
func (s *MultiTxSnapshot) updateCodeChange(change codeChange) {
	if s.objectChanged(*change.account) {
		return
	}
	if _, ok := s.accountCode[*change.account]; !ok {
		s.accountCode[*change.account] = change.prevcode
		s.accountCodeHash[*change.account] = change.prevhash
	}
}

// updateResetObjectChange updates the snapshot with the reset object change.
func (s *MultiTxSnapshot) updateResetObjectChange(change resetObjectChange) {
	address := change.prev.address
	if _, ok := s.prevObjects[address]; !ok {
		s.prevObjects[address] = change.prev
	}
}

// updateCreateObjectChange updates the snapshot with the createObjectChange.
func (s *MultiTxSnapshot) updateCreateObjectChange(change createObjectChange) {
	if _, ok := s.prevObjects[*change.account]; !ok {
		s.prevObjects[*change.account] = nil
	}
}

// updateSuicideChange updates the snapshot with the suicide change.
func (s *MultiTxSnapshot) updateSuicideChange(change suicideChange) {
	if s.objectChanged(*change.account) {
		return
	}
	if _, ok := s.accountSuicided[*change.account]; !ok {
		s.accountSuicided[*change.account] = change.prev
	}
	if _, ok := s.accountBalance[*change.account]; !ok {
		s.accountBalance[*change.account] = change.prevbalance
	}
}

// updatePendingStorage updates the snapshot with the pending storage change.
func (s *MultiTxSnapshot) updatePendingStorage(address common.Address, key, value common.Hash, ok bool) {
	if s.objectChanged(address) {
		return
	}
	if _, ok := s.accountStorage[address]; !ok {
		s.accountStorage[address] = make(map[common.Hash]*common.Hash)
	}
	if _, ok := s.accountStorage[address][key]; ok {
		return
	}
	if ok {
		s.accountStorage[address][key] = &value
	} else {
		s.accountStorage[address][key] = nil
	}
}

// updatePendingStatus updates the snapshot with previous pending status.
func (s *MultiTxSnapshot) updatePendingStatus(address common.Address, pending, dirty bool) {
	if !pending {
		s.accountNotPending[address] = struct{}{}
	}
	if !dirty {
		s.accountNotDirty[address] = struct{}{}
	}
}

// updateObjectDeleted updates the snapshot with the object deletion.
func (s *MultiTxSnapshot) updateObjectDeleted(address common.Address, deleted bool) {
	if s.objectChanged(address) {
		return
	}
	if _, ok := s.accountDeleted[address]; !ok {
		s.accountDeleted[address] = deleted
	}
}

// revertState reverts the state to the snapshot.
func (s *MultiTxSnapshot) revertState(st *StateDB) {
	// remove all the logs added
	for txhash, numLogs := range s.numLogsAdded {
		lens := len(st.logs[txhash])
		if lens == numLogs {
			delete(st.logs, txhash)
		} else {
			st.logs[txhash] = st.logs[txhash][:lens-numLogs]
		}
		st.logSize -= uint(numLogs)
	}

	// restore the objects
	for address, object := range s.prevObjects {
		if object == nil {
			delete(st.stateObjects, address)
		} else {
			st.stateObjects[address] = object
		}
	}

	// restore storage
	for address, storage := range s.accountStorage {
		for key, value := range storage {
			if value == nil {
				delete(st.stateObjects[address].pendingStorage, key)
			} else {
				st.stateObjects[address].pendingStorage[key] = *value
			}
		}
	}

	// restore balance
	for address, balance := range s.accountBalance {
		st.stateObjects[address].setBalance(balance)
	}
	// restore nonce
	for address, nonce := range s.accountNonce {
		st.stateObjects[address].setNonce(nonce)
	}
	// restore code
	for address, code := range s.accountCode {
		st.stateObjects[address].setCode(common.BytesToHash(s.accountCodeHash[address]), code)
	}
	// restore suicided
	for address, suicided := range s.accountSuicided {
		st.stateObjects[address].suicided = suicided
	}
	// restore deleted
	for address, deleted := range s.accountDeleted {
		st.stateObjects[address].deleted = deleted
	}

	// restore pending status
	for address := range s.accountNotPending {
		delete(st.stateObjectsPending, address)
	}
	for address := range s.accountNotDirty {
		delete(st.stateObjectsDirty, address)
	}
}
