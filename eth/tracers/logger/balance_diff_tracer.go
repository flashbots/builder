package logger

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
)

// BalanceChangeTracer is a tracer that captures the balance changes of an address before and after each transaction
type BalanceChangeTracer struct {
	address     common.Address
	outerLogger vm.EVMLogger
	stateDB     vm.StateDB

	balanceChanges []*big.Int
	tempBalance    *big.Int
}

func NewBalanceChangeTracer(address common.Address, outerLogger vm.EVMLogger, stateDB vm.StateDB) *BalanceChangeTracer {
	return &BalanceChangeTracer{
		address:     address,
		outerLogger: outerLogger,
		stateDB:     stateDB,

		balanceChanges: nil,
		tempBalance:    new(big.Int),
	}
}

// GetBalanceChanges returns the balance changes of the address during the execution of the transaction
// It should be called after all transactions were executed with this tracer
func (b *BalanceChangeTracer) GetBalanceChanges() []*big.Int {
	return b.balanceChanges
}

func (b *BalanceChangeTracer) CaptureTxStart(gasLimit uint64) {
	b.tempBalance.Set(b.stateDB.GetBalance(b.address))
	if b.outerLogger != nil {
		b.outerLogger.CaptureTxStart(gasLimit)
	}
}

func (b *BalanceChangeTracer) CaptureTxEnd(restGas uint64) {
	balanceChange := new(big.Int).Sub(b.stateDB.GetBalance(b.address), b.tempBalance)
	b.balanceChanges = append(b.balanceChanges, balanceChange)

	if b.outerLogger != nil {
		b.outerLogger.CaptureTxEnd(restGas)
	}
}

func (b *BalanceChangeTracer) CaptureStart(env *vm.EVM, from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int) {
	if b.outerLogger != nil {
		b.outerLogger.CaptureStart(env, from, to, create, input, gas, value)
	}
}

func (b *BalanceChangeTracer) CaptureEnd(output []byte, gasUsed uint64, err error) {
	if b.outerLogger != nil {
		b.outerLogger.CaptureEnd(output, gasUsed, err)
	}
}

func (b *BalanceChangeTracer) CaptureEnter(typ vm.OpCode, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	if b.outerLogger != nil {
		b.outerLogger.CaptureEnter(typ, from, to, input, gas, value)
	}
}

func (b *BalanceChangeTracer) CaptureExit(output []byte, gasUsed uint64, err error) {
	if b.outerLogger != nil {
		b.outerLogger.CaptureExit(output, gasUsed, err)
	}
}

func (b *BalanceChangeTracer) CaptureState(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, rData []byte, depth int, err error) {
	if b.outerLogger != nil {
		b.outerLogger.CaptureState(pc, op, gas, cost, scope, rData, depth, err)
	}
}

func (b *BalanceChangeTracer) CaptureFault(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, depth int, err error) {
	if b.outerLogger != nil {
		b.outerLogger.CaptureFault(pc, op, gas, cost, scope, depth, err)
	}
}
