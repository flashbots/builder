// Copyright 2014 The go-ethereum Authors
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

package miner

import (
	"container/heap"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/holiman/uint256"
)

type _Order interface {
	AsTx() *txpool.LazyTransaction
	AsBundle() *types.SimulatedBundle
	AsSBundle() *types.SimSBundle
}

type _TxOrder struct {
	tx *txpool.LazyTransaction
}

func (o _TxOrder) AsTx() *txpool.LazyTransaction    { return o.tx }
func (o _TxOrder) AsBundle() *types.SimulatedBundle { return nil }
func (o _TxOrder) AsSBundle() *types.SimSBundle     { return nil }

type _BundleOrder struct {
	bundle *types.SimulatedBundle
}

func (o _BundleOrder) AsTx() *txpool.LazyTransaction    { return nil }
func (o _BundleOrder) AsBundle() *types.SimulatedBundle { return o.bundle }
func (o _BundleOrder) AsSBundle() *types.SimSBundle     { return nil }

type _SBundleOrder struct {
	sbundle *types.SimSBundle
}

func (o _SBundleOrder) AsTx() *txpool.LazyTransaction    { return nil }
func (o _SBundleOrder) AsBundle() *types.SimulatedBundle { return nil }
func (o _SBundleOrder) AsSBundle() *types.SimSBundle     { return o.sbundle }

// txWithMinerFee wraps a transaction with its gas price or effective miner gasTipCap
type txWithMinerFee struct {
	order _Order
	from  common.Address
	fees  *uint256.Int
}

func (t *txWithMinerFee) Tx() *txpool.LazyTransaction {
	return t.order.AsTx()
}

func (t *txWithMinerFee) Bundle() *types.SimulatedBundle {
	return t.order.AsBundle()
}

func (t *txWithMinerFee) SBundle() *types.SimSBundle {
	return t.order.AsSBundle()
}

func (t *txWithMinerFee) Price() *uint256.Int {
	return new(uint256.Int).Set(t.fees)
}

func (t *txWithMinerFee) Profit(baseFee *uint256.Int, gasUsed uint64) *uint256.Int {
	if tx := t.Tx(); tx != nil {
		profit := new(uint256.Int).Sub(tx.GasPrice, baseFee)
		if gasUsed != 0 {
			profit.Mul(profit, new(uint256.Int).SetUint64(gasUsed))
		} else {
			profit.Mul(profit, new(uint256.Int).SetUint64(tx.Gas))
		}
		return profit
	} else if bundle := t.Bundle(); bundle != nil {
		return bundle.EthSentToCoinbase
	} else if sbundle := t.SBundle(); sbundle != nil {
		return sbundle.Profit
	} else {
		panic("profit called on unsupported order type")
	}
}

// SetPrice sets the miner fee of the wrapped transaction.
func (t *txWithMinerFee) SetPrice(price *uint256.Int) {
	t.fees.Set(price)
}

// SetProfit sets the profit of the wrapped transaction.
func (t *txWithMinerFee) SetProfit(profit *uint256.Int) {
	if bundle := t.Bundle(); bundle != nil {
		bundle.TotalEth.Set(profit)
	} else if sbundle := t.SBundle(); sbundle != nil {
		sbundle.Profit.Set(profit)
	} else {
		panic("SetProfit called on unsupported order type")
	}
}

// NewBundleWithMinerFee creates a wrapped bundle.
func newBundleWithMinerFee(bundle *types.SimulatedBundle) (*txWithMinerFee, error) {
	minerFee := bundle.MevGasPrice
	return &txWithMinerFee{
		order: _BundleOrder{bundle},
		fees:  minerFee,
	}, nil
}

// NewSBundleWithMinerFee creates a wrapped bundle.
func newSBundleWithMinerFee(sbundle *types.SimSBundle) (*txWithMinerFee, error) {
	minerFee := sbundle.MevGasPrice
	return &txWithMinerFee{
		order: _SBundleOrder{sbundle},
		fees:  minerFee,
	}, nil
}

// newTxWithMinerFee creates a wrapped transaction, calculating the effective
// miner gasTipCap if a base fee is provided.
// Returns error in case of a negative effective miner gasTipCap.
func newTxWithMinerFee(tx *txpool.LazyTransaction, from common.Address, baseFee *uint256.Int) (*txWithMinerFee, error) {
	tip := new(uint256.Int).Set(tx.GasTipCap)
	if baseFee != nil {
		if tx.GasFeeCap.Cmp(baseFee) < 0 {
			return nil, types.ErrGasFeeCapTooLow
		}
		tip = new(uint256.Int).Sub(tx.GasFeeCap, baseFee)
		if tip.Gt(tx.GasTipCap) {
			tip = tx.GasTipCap
		}
	}
	return &txWithMinerFee{
		order: _TxOrder{tx},
		from:  from,
		fees:  tip,
	}, nil
}

// txByPriceAndTime implements both the sort and the heap interface, making it useful
// for all at once sorting as well as individually adding and removing elements.
type txByPriceAndTime []*txWithMinerFee

func (s txByPriceAndTime) Len() int { return len(s) }
func (s txByPriceAndTime) Less(i, j int) bool {
	// If the prices are equal, use the time the transaction was first seen for
	// deterministic sorting
	cmp := s[i].fees.Cmp(s[j].fees)
	if cmp == 0 {
		if s[i].Tx() != nil && s[j].Tx() != nil {
			return s[i].Tx().Time.Before(s[j].Tx().Time)
		} else if s[i].Bundle() != nil && s[j].Bundle() != nil {
			return s[i].Bundle().TotalGasUsed <= s[j].Bundle().TotalGasUsed
		} else if s[i].Bundle() != nil {
			return false
		}

		return true
	}
	return cmp > 0
}
func (s txByPriceAndTime) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

func (s *txByPriceAndTime) Push(x interface{}) {
	*s = append(*s, x.(*txWithMinerFee))
}

func (s *txByPriceAndTime) Pop() interface{} {
	old := *s
	n := len(old)
	x := old[n-1]
	old[n-1] = nil
	*s = old[0 : n-1]
	return x
}

// transactionsByPriceAndNonce represents a set of transactions that can return
// transactions in a profit-maximizing sorted order, while supporting removing
// entire batches of transactions for non-executable accounts.
type transactionsByPriceAndNonce struct {
	txs     map[common.Address][]*txpool.LazyTransaction // Per account nonce-sorted list of transactions
	heads   txByPriceAndTime                             // Next transaction for each unique account (price heap)
	signer  types.Signer                                 // Signer for the set of transactions
	baseFee *uint256.Int                                 // Current base fee
}

// newTransactionsByPriceAndNonce creates a transaction set that can retrieve
// price sorted transactions in a nonce-honouring way.
//
// Note, the input map is reowned so the caller should not interact any more with
// if after providing it to the constructor.
func newTransactionsByPriceAndNonce(signer types.Signer, txs map[common.Address][]*txpool.LazyTransaction, bundles []types.SimulatedBundle, sbundles []*types.SimSBundle, baseFee *big.Int) *transactionsByPriceAndNonce {
	// Convert the basefee from header format to uint256 format
	var baseFeeUint *uint256.Int
	if baseFee != nil {
		baseFeeUint = uint256.MustFromBig(baseFee)
	}
	// Initialize a price and received time based heap with the head transactions
	heads := make(txByPriceAndTime, 0, len(txs))

	for i := range sbundles {
		wrapped, err := newSBundleWithMinerFee(sbundles[i])
		if err != nil {
			continue
		}
		heads = append(heads, wrapped)
	}

	for i := range bundles {
		wrapped, err := newBundleWithMinerFee(&bundles[i])
		if err != nil {
			continue
		}
		heads = append(heads, wrapped)
	}

	for from, accTxs := range txs {
		wrapped, err := newTxWithMinerFee(accTxs[0], from, baseFeeUint)
		if err != nil {
			delete(txs, from)
			continue
		}
		heads = append(heads, wrapped)
		txs[from] = accTxs[1:]
	}
	heap.Init(&heads)

	// Assemble and return the transaction set
	return &transactionsByPriceAndNonce{
		txs:     txs,
		heads:   heads,
		signer:  signer,
		baseFee: baseFeeUint,
	}
}

// Peek returns the next transaction by price.
func (t *transactionsByPriceAndNonce) Peek() *txWithMinerFee {
	if len(t.heads) == 0 {
		return nil
	}
	return t.heads[0]
}

// Shift replaces the current best head with the next one from the same account.
func (t *transactionsByPriceAndNonce) Shift() {
	acc := t.heads[0].from
	if txs, ok := t.txs[acc]; ok && len(txs) > 0 {
		if wrapped, err := newTxWithMinerFee(txs[0], acc, t.baseFee); err == nil {
			t.heads[0], t.txs[acc] = wrapped, txs[1:]
			heap.Fix(&t.heads, 0)
			return
		}
	}
	heap.Pop(&t.heads)
}

// Pop removes the best transaction, *not* replacing it with the next one from
// the same account. This should be used when a transaction cannot be executed
// and hence all subsequent ones should be discarded from the same account.
func (t *transactionsByPriceAndNonce) Pop() {
	heap.Pop(&t.heads)
}

// ShiftAndPushByAccountForTx attempts to update the transaction list associated with a given account address
// based on the input transaction account. If the associated account exists and has additional transactions,
// the top of the transaction list is popped and pushed to the heap.
// Note that this operation should only be performed when the head transaction on the heap is different from the
// input transaction. This operation is useful in scenarios where the current best head transaction for an account
// was already popped from the heap and we want to process the next one from the same account.
func (t *transactionsByPriceAndNonce) ShiftAndPushByAccountForTx(tx *types.Transaction) {
	if tx == nil {
		return
	}

	acc, _ := types.Sender(t.signer, tx)
	if txs, exists := t.txs[acc]; exists && len(txs) > 0 {
		if wrapped, err := newTxWithMinerFee(txs[0], acc, t.baseFee); err == nil {
			t.txs[acc] = txs[1:]
			heap.Push(&t.heads, wrapped)
		}
	}
}

func (t *transactionsByPriceAndNonce) Push(tx *txWithMinerFee) {
	if tx == nil {
		return
	}

	heap.Push(&t.heads, tx)
}

// Empty returns if the price heap is empty. It can be used to check it simpler
// than calling peek and checking for nil return.
func (t *transactionsByPriceAndNonce) Empty() bool {
	return len(t.heads) == 0
}

// Clear removes the entire content of the heap.
func (t *transactionsByPriceAndNonce) Clear() {
	t.heads, t.txs = nil, nil
}
