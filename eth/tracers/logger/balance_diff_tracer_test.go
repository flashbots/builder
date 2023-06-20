package logger

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/stretchr/testify/require"
)

type dummyStateDB struct {
	state.StateDB
	address common.Address
	balance *big.Int
}

func (db *dummyStateDB) GetBalance(address common.Address) *big.Int {
	if address == db.address {
		return db.balance
	} else {
		return big.NewInt(0)
	}
}

func Test_balanceChangeTracer(t *testing.T) {
	address := common.HexToAddress("0x123")
	stateDB := &dummyStateDB{address: address}

	tracer := NewBalanceChangeTracer(address, nil, stateDB)

	// before the block balance is 100
	stateDB.balance = big.NewInt(100)

	// 1-st tx, gain of 7
	tracer.CaptureTxStart(0)
	stateDB.balance = big.NewInt(107)
	tracer.CaptureTxEnd(0)

	// 2-end tx, gain of 17
	tracer.CaptureTxStart(0)
	stateDB.balance = big.NewInt(124)
	tracer.CaptureTxEnd(0)

	// 3-rd tx, loss of 5
	tracer.CaptureTxStart(0)
	stateDB.balance = big.NewInt(119)
	tracer.CaptureTxEnd(0)

	// 4-rd tx, gain of 3
	tracer.CaptureTxStart(0)
	stateDB.balance = big.NewInt(122)
	tracer.CaptureTxEnd(0)

	result := tracer.GetBalanceChanges()
	expectedResult := []*big.Int{big.NewInt(7), big.NewInt(17), big.NewInt(-5), big.NewInt(3)}

	require.Equal(t, expectedResult, result)
}
