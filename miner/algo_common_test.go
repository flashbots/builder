package miner

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"sync/atomic"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

const GasLimit uint64 = 30000000

var (
	// Pay proxy is a contract that sends msg.value to address specified in calldata[0..32]
	payProxyAddress = common.HexToAddress("0x1100000000000000000000000000000000000000")
	payProxyCode    = hexutil.MustDecode("0x6000600060006000346000356000f1")
	// log contract logs value that it receives
	logContractAddress = common.HexToAddress("0x2200000000000000000000000000000000000000")
	logContractCode    = hexutil.MustDecode("0x346000523460206000a1")
)

type signerList struct {
	config    *params.ChainConfig
	signers   []*ecdsa.PrivateKey
	addresses []common.Address
	nonces    []uint64
}

func simulateBundle(env *environment, bundle types.MevBundle, chData chainData, interrupt *atomic.Int32) (types.SimulatedBundle, error) {
	// NOTE(wazzymandias): We are referencing the environment StateDB here - notice that it is not a copy.
	// For test scenarios where bundles depend on previous bundle transactions to succeed, it is
	// necessary to reference the same StateDB in order to avoid nonce too high errors.
	// As a result, it is recommended that the caller make a copy before invoking this function, in order to
	// ensure transaction serializability across bundles.
	stateDB := env.state
	gasPool := new(core.GasPool).AddGas(env.header.GasLimit)

	var totalGasUsed uint64
	gasFees := uint256.NewInt(0)
	ethSentToCoinbase := uint256.NewInt(0)

	for i, tx := range bundle.Txs {
		if checkInterrupt(interrupt) {
			return types.SimulatedBundle{}, errInterrupt
		}

		if env.header.BaseFee != nil && tx.Type() == 2 {
			// Sanity check for extremely large numbers
			if tx.GasFeeCap().BitLen() > 256 {
				return types.SimulatedBundle{}, core.ErrFeeCapVeryHigh
			}
			if tx.GasTipCap().BitLen() > 256 {
				return types.SimulatedBundle{}, core.ErrTipVeryHigh
			}
			// Ensure gasFeeCap is greater than or equal to gasTipCap.
			if tx.GasFeeCapIntCmp(tx.GasTipCap()) < 0 {
				return types.SimulatedBundle{}, core.ErrTipAboveFeeCap
			}
		}

		stateDB.SetTxContext(tx.Hash(), i+env.tcount)
		coinbaseBalanceBefore := stateDB.GetBalance(env.coinbase)

		var tempGasUsed uint64
		receipt, err := core.ApplyTransaction(chData.chainConfig, chData.chain, &env.coinbase, gasPool, stateDB, env.header, tx, &tempGasUsed, *chData.chain.GetVMConfig(), nil)
		if err != nil {
			return types.SimulatedBundle{}, err
		}
		if receipt.Status == types.ReceiptStatusFailed && !containsHash(bundle.RevertingTxHashes, receipt.TxHash) {
			return types.SimulatedBundle{}, errors.New("failed tx")
		}

		totalGasUsed += receipt.GasUsed

		_, err = types.Sender(env.signer, tx)
		if err != nil {
			return types.SimulatedBundle{}, err
		}

		// see NOTE below
		//txInPendingPool := false
		//if accountTxs, ok := pendingTxs[from]; ok {
		//	// check if tx is in pending pool
		//	txNonce := tx.Nonce()
		//
		//	for _, accountTx := range accountTxs {
		//		if accountTx.Nonce() == txNonce {
		//			txInPendingPool = true
		//			break
		//		}
		//	}
		//}

		gasUsed := new(uint256.Int).SetUint64(receipt.GasUsed)
		gasPrice, err := tx.EffectiveGasTip(env.header.BaseFee)
		if err != nil {
			return types.SimulatedBundle{}, err
		}
		gasFeesTx := gasUsed.Mul(gasUsed, uint256.MustFromBig(gasPrice))
		coinbaseBalanceAfter := stateDB.GetBalance(env.coinbase)
		coinbaseDelta := uint256.NewInt(0).Sub(coinbaseBalanceAfter, coinbaseBalanceBefore)
		coinbaseDelta.Sub(coinbaseDelta, gasFeesTx)
		ethSentToCoinbase.Add(ethSentToCoinbase, coinbaseDelta)

		// NOTE - it differs from prod!, if changed - change in commit bundle too
		//if !txInPendingPool {
		//	// If tx is not in pending pool, count the gas fees
		//	gasFees.Add(gasFees, gasFeesTx)
		//}
		gasFees.Add(gasFees, gasFeesTx)
	}

	totalEth := new(uint256.Int).Add(ethSentToCoinbase, gasFees)

	return types.SimulatedBundle{
		MevGasPrice:       new(uint256.Int).Div(totalEth, new(uint256.Int).SetUint64(totalGasUsed)),
		TotalEth:          totalEth,
		EthSentToCoinbase: ethSentToCoinbase,
		TotalGasUsed:      totalGasUsed,
		OriginalBundle:    bundle,
	}, nil
}

func (sig signerList) signTx(i int, gas uint64, gasTipCap, gasFeeCap *big.Int, to common.Address, value *big.Int, data []byte) *types.Transaction {
	txData := &types.DynamicFeeTx{
		ChainID:   sig.config.ChainID,
		Nonce:     sig.nonces[i],
		GasTipCap: gasTipCap,
		GasFeeCap: gasFeeCap,
		Gas:       gas,
		To:        &to,
		Value:     value,
		Data:      data,
	}
	sig.nonces[i] += 1

	return types.MustSignNewTx(sig.signers[i], types.LatestSigner(sig.config), txData)
}

func genSignerList(len int, config *params.ChainConfig) signerList {
	res := signerList{
		config:    config,
		signers:   make([]*ecdsa.PrivateKey, len),
		addresses: make([]common.Address, len),
		nonces:    make([]uint64, len),
	}

	for i := 0; i < len; i++ {
		privKey, err := crypto.ToECDSA(crypto.Keccak256(big.NewInt(int64(i)).Bytes()))
		if err != nil {
			panic(fmt.Sprint("cant create priv key", err))
		}
		res.signers[i] = privKey
		res.addresses[i] = crypto.PubkeyToAddress(privKey.PublicKey)
	}
	return res
}

func genGenesisAlloc(sign signerList, contractAddr []common.Address, contractCode [][]byte) types.GenesisAlloc {
	genesisAlloc := make(types.GenesisAlloc)
	for i := 0; i < len(sign.signers); i++ {
		genesisAlloc[sign.addresses[i]] = types.Account{
			Balance: big.NewInt(1000000000000000000), // 1 ether
			Nonce:   sign.nonces[i],
		}
	}

	for i, address := range contractAddr {
		genesisAlloc[address] = types.Account{
			Balance: new(big.Int),
			Code:    contractCode[i],
		}
	}

	return genesisAlloc
}

func genTestSetup(gasLimit uint64) (*state.StateDB, chainData, signerList) {
	config := params.AllEthashProtocolChanges
	signerList := genSignerList(10, params.AllEthashProtocolChanges)
	genesisAlloc := genGenesisAlloc(signerList, []common.Address{payProxyAddress, logContractAddress}, [][]byte{payProxyCode, logContractCode})

	stateDB, chainData := genTestSetupWithAlloc(config, genesisAlloc, gasLimit)
	return stateDB, chainData, signerList
}

func genTestSetupWithAlloc(config *params.ChainConfig, alloc types.GenesisAlloc, gasLimit uint64) (*state.StateDB, chainData) {
	db := rawdb.NewMemoryDatabase()

	gspec := &core.Genesis{
		Config:   config,
		Alloc:    alloc,
		GasLimit: gasLimit,
	}
	_ = gspec.MustCommit(db, triedb.NewDatabase(db, triedb.HashDefaults))

	chain, _ := core.NewBlockChain(db, &core.CacheConfig{TrieDirtyDisabled: true}, gspec, nil, ethash.NewFaker(), vm.Config{}, nil, nil)

	stateDB, _ := state.New(chain.CurrentHeader().Root, state.NewDatabase(db), nil)

	return stateDB, chainData{config, chain, nil}
}

func newEnvironment(data chainData, state *state.StateDB, coinbase common.Address, gasLimit uint64, baseFee *big.Int) *environment {
	currentBlock := data.chain.CurrentBlock()
	// Note the passed coinbase may be different with header.Coinbase.
	return &environment{
		signer:   types.MakeSigner(data.chainConfig, currentBlock.Number, currentBlock.Time),
		state:    state,
		gasPool:  new(core.GasPool).AddGas(gasLimit),
		coinbase: coinbase,
		header: &types.Header{
			Coinbase:   coinbase,
			ParentHash: currentBlock.Hash(),
			Number:     new(big.Int).Add(currentBlock.Number, big.NewInt(1)),
			GasLimit:   gasLimit,
			GasUsed:    0,
			BaseFee:    baseFee,
			Difficulty: big.NewInt(0),
		},
		profit: new(uint256.Int),
	}
}

func TestTxCommit(t *testing.T) {
	statedb, chData, signers := genTestSetup(GasLimit)

	env := newEnvironment(chData, statedb, signers.addresses[0], GasLimit, big.NewInt(1))
	envDiff := newEnvironmentDiff(env)

	tx := signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{})

	receipt, i, err := envDiff.commitTx(tx, chData)
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

	if envDiff.gasPool.AddGas(receipt.GasUsed).Gas() != GasLimit {
		t.Fatal("envDiff gas pool incorrect")
	}
	if envDiff.header.GasUsed != receipt.GasUsed {
		t.Fatal("envDiff gas used is incorrect")
	}
	if len(envDiff.newReceipts) != 1 {
		t.Fatal("envDiff receipts incorrect")
	}
	if len(envDiff.newTxs) != 1 {
		t.Fatal("envDiff txs incorrect")
	}
}

func TestBundleCommit(t *testing.T) {
	algoConf := defaultAlgorithmConfig
	statedb, chData, signers := genTestSetup(GasLimit)

	env := newEnvironment(chData, statedb, signers.addresses[0], GasLimit, big.NewInt(1))
	envDiff := newEnvironmentDiff(env)

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

	err = envDiff.commitBundle(&simBundle, chData, nil, algoConf)
	if err != nil {
		t.Fatal("Failed to commit bundle", err)
	}

	if len(envDiff.newTxs) != 2 {
		t.Fatal("Incorrect new txs")
	}
	if len(envDiff.newReceipts) != 2 {
		t.Fatal("Incorrect receipts txs")
	}
	if envDiff.gasPool.AddGas(21000*2).Gas() != GasLimit {
		t.Fatal("Gas pool incorrect update")
	}
}

func TestErrorTxCommit(t *testing.T) {
	statedb, chData, signers := genTestSetup(GasLimit)

	env := newEnvironment(chData, statedb, signers.addresses[0], GasLimit, big.NewInt(1))
	envDiff := newEnvironmentDiff(env)

	signers.nonces[1] = 10
	tx := signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{})

	_, i, err := envDiff.commitTx(tx, chData)
	if err == nil {
		t.Fatal("committed incorrect transaction:", err)
	}
	if i != popTx {
		t.Fatal("incorrect shift value")
	}

	if envDiff.gasPool.Gas() != GasLimit {
		t.Fatal("envDiff gas pool incorrect")
	}
	if envDiff.header.GasUsed != 0 {
		t.Fatal("envDiff gas used incorrect")
	}
	if envDiff.newProfit.Sign() != 0 {
		t.Fatal("envDiff new profit incorrect")
	}
	if len(envDiff.newReceipts) != 0 {
		t.Fatal("envDiff receipts incorrect")
	}
	if len(envDiff.newTxs) != 0 {
		t.Fatal("envDiff txs incorrect")
	}
}

func TestCommitTxOverGasLimit(t *testing.T) {
	statedb, chData, signers := genTestSetup(GasLimit)

	env := newEnvironment(chData, statedb, signers.addresses[0], 21000, big.NewInt(1))
	envDiff := newEnvironmentDiff(env)

	tx1 := signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{})
	tx2 := signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{})

	receipt, i, err := envDiff.commitTx(tx1, chData)
	if err != nil {
		t.Fatal("can't commit transaction:", err)
	}
	if receipt.Status != 1 {
		t.Fatal("tx failed", receipt)
	}
	if i != shiftTx {
		t.Fatal("incorrect shift value")
	}

	if envDiff.gasPool.Gas() != 0 {
		t.Fatal("Env diff gas pool is not drained")
	}

	_, _, err = envDiff.commitTx(tx2, chData)
	require.Error(t, err, "committed tx over gas limit")
}

func TestErrorBundleCommit(t *testing.T) {
	statedb, chData, signers := genTestSetup(GasLimit)

	env := newEnvironment(chData, statedb, signers.addresses[0], 21000*2, big.NewInt(1))
	envDiff := newEnvironmentDiff(env)

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

	_, _, err = envDiff.commitTx(tx0, chData)
	if err != nil {
		t.Fatal("Failed to commit tx0", err)
	}

	gasPoolBefore := *envDiff.gasPool
	gasUsedBefore := envDiff.header.GasUsed
	newProfitBefore := new(uint256.Int).Set(envDiff.newProfit)
	balanceBefore := envDiff.state.GetBalance(signers.addresses[2])

	err = envDiff.commitBundle(&simBundle, chData, nil, defaultAlgorithmConfig)
	if err == nil {
		t.Fatal("Committed failed bundle", err)
	}

	if *envDiff.gasPool != gasPoolBefore {
		t.Fatal("gasPool changed")
	}

	if envDiff.header.GasUsed != gasUsedBefore {
		t.Fatal("gasUsed changed")
	}

	balanceAfter := envDiff.state.GetBalance(signers.addresses[2])
	if balanceAfter.Cmp(balanceBefore) != 0 {
		t.Fatal("balance changed")
	}

	if envDiff.newProfit.Cmp(newProfitBefore) != 0 {
		t.Fatal("newProfit changed")
	}

	if len(envDiff.newTxs) != 1 {
		t.Fatal("Incorrect new txs")
	}
	if len(envDiff.newReceipts) != 1 {
		t.Fatal("Incorrect receipts txs")
	}
}

func TestBlacklist(t *testing.T) {
	statedb, chData, signers := genTestSetup(GasLimit)

	env := newEnvironment(chData, statedb, signers.addresses[0], GasLimit, big.NewInt(1))
	envDiff := newEnvironmentDiff(env)

	beforeRoot := statedb.IntermediateRoot(true)

	blacklist := map[common.Address]struct{}{
		signers.addresses[3]: {},
	}
	chData.blacklist = blacklist

	gasPoolBefore := *envDiff.gasPool
	gasUsedBefore := envDiff.header.GasUsed
	balanceBefore := envDiff.state.GetBalance(signers.addresses[3])

	tx := signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[3], big.NewInt(77), []byte{})
	_, _, err := envDiff.commitTx(tx, chData)
	if err == nil {
		t.Fatal("committed blacklisted transaction: to")
	}

	tx = signers.signTx(3, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[1], big.NewInt(88), []byte{})
	_, _, err = envDiff.commitTx(tx, chData)
	if err == nil {
		t.Fatal("committed blacklisted transaction: sender")
	}

	calldata := make([]byte, 32-20, 20)
	calldata = append(calldata, signers.addresses[3].Bytes()...)

	tx = signers.signTx(4, 40000, big.NewInt(0), big.NewInt(1), payProxyAddress, big.NewInt(99), calldata)
	_, _, err = envDiff.commitTx(tx, chData)
	if err == nil {
		t.Fatal("committed blacklisted transaction: trace")
	}

	tx = signers.signTx(5, 40000, big.NewInt(0), big.NewInt(1), payProxyAddress, big.NewInt(0), calldata)
	_, _, err = envDiff.commitTx(tx, chData)
	if err == nil {
		t.Fatal("committed blacklisted transaction: trace, zero value")
	}

	tx = signers.signTx(6, 30000, big.NewInt(0), big.NewInt(1), payProxyAddress, big.NewInt(99), calldata)
	_, _, err = envDiff.commitTx(tx, chData)
	if err == nil {
		t.Fatal("committed blacklisted transaction: trace, failed tx")
	}

	if *envDiff.gasPool != gasPoolBefore {
		t.Fatal("gasPool changed")
	}

	if envDiff.header.GasUsed != gasUsedBefore {
		t.Fatal("gasUsed changed")
	}

	if envDiff.newProfit.Sign() != 0 {
		t.Fatal("newProfit changed")
	}

	if envDiff.state.GetBalance(signers.addresses[3]).Cmp(balanceBefore) != 0 {
		t.Fatal("blacklisted balance changed")
	}

	if len(envDiff.newTxs) != 0 {
		t.Fatal("newTxs changed")
	}

	if len(envDiff.newReceipts) != 0 {
		t.Fatal("newReceipts changed")
	}

	afterRoot := statedb.IntermediateRoot(true)
	if beforeRoot != afterRoot {
		t.Fatal("statedb root changed")
	}
}

func TestGetSealingWorkAlgos(t *testing.T) {
	t.Cleanup(func() {
		testConfig.AlgoType = ALGO_MEV_GETH
	})

	for _, algoType := range []AlgoType{ALGO_MEV_GETH, ALGO_GREEDY, ALGO_GREEDY_BUCKETS, ALGO_GREEDY_MULTISNAP, ALGO_GREEDY_BUCKETS_MULTISNAP} {
		local := new(params.ChainConfig)
		*local = *ethashChainConfig
		local.TerminalTotalDifficulty = big.NewInt(0)
		testConfig.AlgoType = algoType
		testGetSealingWork(t, local, ethash.NewFaker())
	}
}

func TestGetSealingWorkAlgosWithProfit(t *testing.T) {
	t.Cleanup(func() {
		testConfig.AlgoType = ALGO_MEV_GETH
		testConfig.BuilderTxSigningKey = nil
	})

	for _, algoType := range []AlgoType{ALGO_GREEDY, ALGO_GREEDY_BUCKETS, ALGO_GREEDY_MULTISNAP, ALGO_GREEDY_BUCKETS_MULTISNAP} {
		var err error
		testConfig.BuilderTxSigningKey, err = crypto.GenerateKey()
		require.NoError(t, err)
		testConfig.AlgoType = algoType
		t.Logf("running for %s", algoType.String())
		testBundles(t)
	}
}

func TestPayoutTxUtils(t *testing.T) {
	availableFunds := big.NewInt(50000000000000000) // 0.05 eth

	statedb, chData, signers := genTestSetup(GasLimit)

	env := newEnvironment(chData, statedb, signers.addresses[0], GasLimit, big.NewInt(1))

	// Sending payment to the plain EOA
	gas, isEOA, err := estimatePayoutTxGas(env, signers.addresses[1], signers.addresses[2], signers.signers[1], chData)
	require.Equal(t, uint64(21000), gas)
	require.True(t, isEOA)
	require.NoError(t, err)

	expectedPayment := new(big.Int).Sub(availableFunds, big.NewInt(21000))
	balanceBefore := env.state.GetBalance(signers.addresses[2]).ToBig()
	rec, err := insertPayoutTx(env, signers.addresses[1], signers.addresses[2], gas, isEOA, availableFunds, signers.signers[1], chData)
	balanceAfter := env.state.GetBalance(signers.addresses[2]).ToBig()
	require.NoError(t, err)
	require.NotNil(t, rec)
	require.Equal(t, types.ReceiptStatusSuccessful, rec.Status)
	require.Equal(t, uint64(21000), rec.GasUsed)
	require.True(t, new(big.Int).Sub(balanceAfter, balanceBefore).Cmp(expectedPayment) == 0)
	require.Equal(t, env.state.GetNonce(signers.addresses[1]), uint64(1))

	// Sending payment to the contract that logs event of the amount
	gas, isEOA, err = estimatePayoutTxGas(env, signers.addresses[1], logContractAddress, signers.signers[1], chData)
	require.Equal(t, uint64(22025), gas)
	require.False(t, isEOA)
	require.NoError(t, err)

	expectedPayment = new(big.Int).Sub(availableFunds, big.NewInt(22025))
	balanceBefore = env.state.GetBalance(logContractAddress).ToBig()
	rec, err = insertPayoutTx(env, signers.addresses[1], logContractAddress, gas, isEOA, availableFunds, signers.signers[1], chData)
	balanceAfter = env.state.GetBalance(logContractAddress).ToBig()
	require.NoError(t, err)
	require.NotNil(t, rec)
	require.Equal(t, types.ReceiptStatusSuccessful, rec.Status)
	require.Equal(t, uint64(22025), rec.GasUsed)
	require.True(t, new(big.Int).Sub(balanceAfter, balanceBefore).Cmp(expectedPayment) == 0)
	require.Equal(t, env.state.GetNonce(signers.addresses[1]), uint64(2))

	// Try requesting less gas for contract tx. We request 21k gas, but we must pay 22025
	expectedPayment = new(big.Int).Sub(availableFunds, big.NewInt(22025))
	balanceBefore = env.state.GetBalance(logContractAddress).ToBig()
	rec, err = insertPayoutTx(env, signers.addresses[1], logContractAddress, 21000, isEOA, availableFunds, signers.signers[1], chData)
	balanceAfter = env.state.GetBalance(logContractAddress).ToBig()
	require.NoError(t, err)
	require.NotNil(t, rec)
	require.Equal(t, types.ReceiptStatusSuccessful, rec.Status)
	require.Equal(t, uint64(22025), rec.GasUsed)
	require.True(t, new(big.Int).Sub(balanceAfter, balanceBefore).Cmp(expectedPayment) == 0)
	require.Equal(t, env.state.GetNonce(signers.addresses[1]), uint64(3))

	// errors

	_, err = insertPayoutTx(env, signers.addresses[1], signers.addresses[2], 21000, true, availableFunds, signers.signers[2], chData)
	require.ErrorContains(t, err, "incorrect sender private key")
	_, err = insertPayoutTx(env, signers.addresses[1], logContractAddress, 23000, false, availableFunds, signers.signers[2], chData)
	require.ErrorContains(t, err, "incorrect sender private key")

	_, err = insertPayoutTx(env, signers.addresses[1], signers.addresses[2], 21000, true, big.NewInt(21000-1), signers.signers[1], chData)
	require.ErrorContains(t, err, "not enough funds available")
	_, err = insertPayoutTx(env, signers.addresses[1], logContractAddress, 23000, false, big.NewInt(23000-1), signers.signers[1], chData)
	require.ErrorContains(t, err, "not enough funds available")

	_, err = insertPayoutTx(env, signers.addresses[1], signers.addresses[2], 20000, true, availableFunds, signers.signers[1], chData)
	require.ErrorContains(t, err, "not enough gas")

	require.Equal(t, env.state.GetNonce(signers.addresses[1]), uint64(3))
}
