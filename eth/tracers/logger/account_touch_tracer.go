// Copyright 2022 flashbots
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

package logger

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
	"math/big"
	"time"
)

type AccountTouchTracer struct {
	touched map[common.Address]struct{}
}

// NewAccountTouchTracer creates new AccountTouchTracer
// that collect all addresses touched in the given tx
// including tx sender and tx.to from the top level call
func NewAccountTouchTracer() *AccountTouchTracer {
	return &AccountTouchTracer{
		touched: map[common.Address]struct{}{},
	}
}

func (t *AccountTouchTracer) TouchedAddresses() []common.Address {
	result := make([]common.Address, 0, len(t.touched))

	for address := range t.touched {
		result = append(result, address)
	}
	return result
}

func (t *AccountTouchTracer) CaptureTxStart(uint64) {}

func (t *AccountTouchTracer) CaptureTxEnd(uint64) {}

func (t *AccountTouchTracer) CaptureStart(_ *vm.EVM, from common.Address, to common.Address, _ bool, _ []byte, _ uint64, _ *big.Int) {
	t.touched[from] = struct{}{}
	t.touched[to] = struct{}{}
}

func (t *AccountTouchTracer) CaptureEnd([]byte, uint64, time.Duration, error) {}

func (t *AccountTouchTracer) CaptureEnter(_ vm.OpCode, _ common.Address, to common.Address, _ []byte, _ uint64, _ *big.Int) {
	t.touched[to] = struct{}{}
}

func (t *AccountTouchTracer) CaptureExit([]byte, uint64, error) {}

func (t *AccountTouchTracer) CaptureState(uint64, vm.OpCode, uint64, uint64, *vm.ScopeContext, []byte, int, error) {
}

func (t *AccountTouchTracer) CaptureFault(uint64, vm.OpCode, uint64, uint64, *vm.ScopeContext, int, error) {
}
