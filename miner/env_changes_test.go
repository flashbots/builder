package miner

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

func TestTxCommitSnaps(t *testing.T) {
	statedb, chData, signers := genTestSetup(GasLimit)

	env := newEnvironment(chData, statedb, signers.addresses[0], GasLimit, big.NewInt(1))
	tx := signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{})

	changes, err := newEnvChanges(env)
	if err != nil {
		t.Fatalf("Error creating changes: %v", err)
	}

	receipt, i, err := changes.commitTx(tx, chData)
	if err != nil {
		t.Fatal("can't commit transaction:", err)
	}
	if receipt.Status != 1 {
		t.Fatal("tx failed", receipt)
	}
	if i != shiftTx {
		t.Fatal("incorrect shift value")
	}

	if env.tcount != 0 {
		t.Fatal("env tcount modified")
	}
	if len(env.receipts) != 0 {
		t.Fatal("env receipts modified")
	}
	if len(env.txs) != 0 {
		t.Fatal("env txs modified")
	}
	if env.gasPool.Gas() != GasLimit {
		t.Fatal("env gas pool modified")
	}

	if changes.gasPool.AddGas(receipt.GasUsed).Gas() != GasLimit {
		t.Fatal("envDiff gas pool incorrect")
	}
	if changes.usedGas != receipt.GasUsed {
		t.Fatal("envDiff gas used is incorrect")
	}
	if len(changes.receipts) != 1 {
		t.Fatal("envDiff receipts incorrect")
	}
	if len(changes.txs) != 1 {
		t.Fatal("envDiff txs incorrect")
	}
}
func TestBundleCommitSnaps(t *testing.T) {
	statedb, chData, signers := genTestSetup(GasLimit)

	algoConf := defaultAlgorithmConfig
	env := newEnvironment(chData, statedb, signers.addresses[0], GasLimit, big.NewInt(1))

	tx1 := signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{})
	tx2 := signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{})

	bundle := types.MevBundle{
		Txs:         types.Transactions{tx1, tx2},
		BlockNumber: env.header.Number,
	}

	envCopy := env.copy()
	simBundle, err := simulateBundle(envCopy, bundle, chData, nil)
	if err != nil {
		t.Fatal("Failed to simulate bundle", err)
	}

	changes, err := newEnvChanges(env)
	if err != nil {
		t.Fatal("can't create env changes", err)
	}

	err = changes.commitBundle(&simBundle, chData, algoConf)
	if err != nil {
		t.Fatal("Failed to commit bundle", err)
	}

	if len(changes.txs) != 2 {
		t.Fatal("Incorrect new txs")
	}
	if len(changes.receipts) != 2 {
		t.Fatal("Incorrect receipts txs")
	}
	if changes.gasPool.AddGas(21000*2).Gas() != GasLimit {
		t.Fatal("Gas pool incorrect update")
	}
}

func TestErrorTxCommitSnaps(t *testing.T) {
	statedb, chData, signers := genTestSetup(GasLimit)

	env := newEnvironment(chData, statedb, signers.addresses[0], GasLimit, big.NewInt(1))
	changes, err := newEnvChanges(env)
	if err != nil {
		t.Fatal("can't create env changes", err)
	}

	signers.nonces[1] = 10
	tx := signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{})

	_, i, err := changes.commitTx(tx, chData)
	if err == nil {
		t.Fatal("committed incorrect transaction:", err)
	}
	if i != popTx {
		t.Fatal("incorrect shift value")
	}

	if changes.gasPool.Gas() != GasLimit {
		t.Fatal("envDiff gas pool incorrect")
	}
	if changes.usedGas != 0 {
		t.Fatal("envDiff gas used incorrect")
	}
	if changes.profit.Sign() != 0 {
		t.Fatal("envDiff new profit incorrect")
	}
	if len(changes.receipts) != 0 {
		t.Fatal("envDiff receipts incorrect")
	}
	if len(changes.receipts) != 0 {
		t.Fatal("envDiff txs incorrect")
	}
}

func TestCommitTxOverGasLimitSnaps(t *testing.T) {
	statedb, chData, signers := genTestSetup(GasLimit)

	env := newEnvironment(chData, statedb, signers.addresses[0], 21000, big.NewInt(1))
	changes, err := newEnvChanges(env)
	if err != nil {
		t.Fatal("can't create env changes", err)
	}

	tx1 := signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{})
	tx2 := signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{})

	receipt, i, err := changes.commitTx(tx1, chData)
	if err != nil {
		t.Fatal("can't commit transaction:", err)
	}
	if receipt.Status != 1 {
		t.Fatal("tx failed", receipt)
	}
	if i != shiftTx {
		t.Fatal("incorrect shift value")
	}

	if changes.gasPool.Gas() != 0 {
		t.Fatal("Env diff gas pool is not drained")
	}

	_, _, err = changes.commitTx(tx2, chData)
	require.Error(t, err, "committed tx over gas limit")
}

func TestErrorBundleCommitSnaps(t *testing.T) {
	statedb, chData, signers := genTestSetup(GasLimit)

	algoConf := defaultAlgorithmConfig
	env := newEnvironment(chData, statedb, signers.addresses[0], 21000*2, big.NewInt(1))

	// This tx will be included before bundle so bundle will fail because of gas limit
	tx0 := signers.signTx(4, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{})

	tx1 := signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{})
	tx2 := signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{})

	bundle := types.MevBundle{
		Txs:         types.Transactions{tx1, tx2},
		BlockNumber: env.header.Number,
	}

	simBundle, err := simulateBundle(env, bundle, chData, nil)
	if err != nil {
		t.Fatal("Failed to simulate bundle", err)
	}

	changes, err := newEnvChanges(env)
	if err != nil {
		t.Fatal("can't create env changes", err)
	}

	_, _, err = changes.commitTx(tx0, chData)
	if err != nil {
		t.Fatal("Failed to commit tx0", err)
	}

	gasPoolBefore := *changes.gasPool
	gasUsedBefore := changes.usedGas
	newProfitBefore := new(uint256.Int).Set(changes.profit)
	balanceBefore := changes.env.state.GetBalance(signers.addresses[2])

	err = changes.commitBundle(&simBundle, chData, algoConf)
	if err == nil {
		t.Fatal("Committed failed bundle", err)
	}

	if *changes.gasPool != gasPoolBefore {
		t.Fatalf("gasPool changed [found: %d, expected: %d]", changes.gasPool.Gas(), gasPoolBefore.Gas())
	}

	if changes.usedGas != gasUsedBefore {
		t.Fatal("gasUsed changed")
	}

	balanceAfter := changes.env.state.GetBalance(signers.addresses[2])
	if balanceAfter.Cmp(balanceBefore) != 0 {
		t.Fatal("balance changed")
	}

	if changes.profit.Cmp(newProfitBefore) != 0 {
		t.Fatal("newProfit changed")
	}

	if len(changes.txs) != 1 {
		t.Fatal("Incorrect new txs")
	}
	if len(changes.receipts) != 1 {
		t.Fatal("Incorrect receipts txs")
	}
}

func TestErrorSBundleCommitSnaps(t *testing.T) {
	statedb, chData, signers := genTestSetup(GasLimit)

	env := newEnvironment(chData, statedb, signers.addresses[0], 21000*2, big.NewInt(1))
	changes, err := newEnvChanges(env)
	if err != nil {
		t.Fatal("can't create env changes", err)
	}

	// This tx will be included before sbundle so sbundle will fail because of gas limit
	tx0 := signers.signTx(4, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{})

	tx1 := signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{})
	tx2 := signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{})

	sbundle := types.SimSBundle{
		Bundle: &types.SBundle{
			Inclusion: types.BundleInclusion{
				BlockNumber:    env.header.Number.Uint64(),
				MaxBlockNumber: env.header.Number.Uint64(),
			},
			Body: []types.BundleBody{
				{
					Tx: tx1,
				},
				{
					Tx: tx2,
				},
			},
		},
		// with such small values this bundle will never be rejected based on insufficient profit
		MevGasPrice: uint256.NewInt(1),
		Profit:      uint256.NewInt(1),
	}

	_, _, err = changes.commitTx(tx0, chData)
	if err != nil {
		t.Fatal("Failed to commit tx0", err)
	}

	gasPoolBefore := *changes.gasPool
	gasUsedBefore := changes.usedGas
	newProfitBefore := new(uint256.Int).Set(changes.profit)
	balanceBefore := changes.env.state.GetBalance(signers.addresses[2])

	err = changes.CommitSBundle(&sbundle, chData, builderPrivKey, defaultAlgorithmConfig)
	if err == nil {
		t.Fatal("Committed failed bundle", err)
	}

	if *changes.gasPool != gasPoolBefore {
		t.Fatalf("gasPool changed [found: %d, expected: %d]", changes.gasPool.Gas(), gasPoolBefore.Gas())
	}

	if changes.usedGas != gasUsedBefore {
		t.Fatal("gasUsed changed")
	}

	balanceAfter := changes.env.state.GetBalance(signers.addresses[2])
	if balanceAfter.Cmp(balanceBefore) != 0 {
		t.Fatal("balance changed")
	}

	if changes.profit.Cmp(newProfitBefore) != 0 {
		t.Fatal("newProfit changed")
	}

	if len(changes.txs) != 1 {
		t.Fatal("Incorrect new txs")
	}
	if len(changes.receipts) != 1 {
		t.Fatal("Incorrect receipts txs")
	}
}

func TestBlacklistSnaps(t *testing.T) {
	statedb, chData, signers := genTestSetup(GasLimit)

	// NOTE: intermediate root hash MUST be generated before env changes are instantiated, otherwise state.MultiTxSnapshot
	// will be invalidated and the test will fail
	beforeRoot := statedb.IntermediateRoot(true)

	env := newEnvironment(chData, statedb, signers.addresses[0], GasLimit, big.NewInt(1))
	changes, err := newEnvChanges(env)
	if err != nil {
		t.Fatal("can't create env changes", err)
	}

	blacklist := map[common.Address]struct{}{
		signers.addresses[3]: {},
	}
	chData.blacklist = blacklist

	gasPoolBefore := *changes.gasPool
	gasUsedBefore := changes.usedGas
	balanceBefore := changes.env.state.GetBalance(signers.addresses[3])

	tx := signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[3], big.NewInt(77), []byte{})
	_, _, err = changes.commitTx(tx, chData)
	if err == nil {
		t.Fatal("committed blacklisted transaction: to")
	}

	tx = signers.signTx(3, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[1], big.NewInt(88), []byte{})
	_, _, err = changes.commitTx(tx, chData)
	if err == nil {
		t.Fatal("committed blacklisted transaction: sender")
	}

	calldata := make([]byte, 32-20, 20)
	calldata = append(calldata, signers.addresses[3].Bytes()...)

	tx = signers.signTx(4, 40000, big.NewInt(0), big.NewInt(1), payProxyAddress, big.NewInt(99), calldata)
	_, _, err = changes.commitTx(tx, chData)
	t.Log("balance", changes.env.state.GetBalance(signers.addresses[3]))

	if err == nil {
		t.Fatal("committed blacklisted transaction: trace")
	}

	err = changes.discard()
	if err != nil {
		t.Fatal("failed reverting changes", err)
	}

	if *changes.gasPool != gasPoolBefore {
		t.Fatalf("gasPool changed [found: %d, expected: %d]", changes.gasPool.Gas(), gasPoolBefore.Gas())
	}

	if changes.usedGas != gasUsedBefore {
		t.Fatal("gasUsed changed")
	}

	if changes.profit.Sign() != 0 {
		t.Fatal("newProfit changed")
	}

	if changes.env.state.GetBalance(signers.addresses[3]).Cmp(balanceBefore) != 0 {
		t.Fatalf("blacklisted balance changed [found: %d, expected: %d]",
			changes.env.state.GetBalance(signers.addresses[3]), balanceBefore)
	}

	if len(changes.txs) != 0 {
		t.Fatal("newTxs changed")
	}

	if len(changes.receipts) != 0 {
		t.Fatal("newReceipts changed")
	}

	afterRoot := statedb.IntermediateRoot(true)
	if beforeRoot != afterRoot {
		t.Fatal("statedb root changed")
	}
}
