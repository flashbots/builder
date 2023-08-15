package miner

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/rlp"

	"github.com/stretchr/testify/require"

	mapset "github.com/deckarep/golang-set/v2"
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

func simulateBundle(env *environment, bundle types.MevBundle, chData chainData, interrupt *int32) (types.SimulatedBundle, error) {
	stateDB := env.state.Copy()
	gasPool := new(core.GasPool).AddGas(env.header.GasLimit)

	var totalGasUsed uint64
	gasFees := big.NewInt(0)
	ethSentToCoinbase := big.NewInt(0)

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

		gasUsed := new(big.Int).SetUint64(receipt.GasUsed)
		gasPrice, err := tx.EffectiveGasTip(env.header.BaseFee)
		if err != nil {
			return types.SimulatedBundle{}, err
		}
		gasFeesTx := gasUsed.Mul(gasUsed, gasPrice)
		coinbaseBalanceAfter := stateDB.GetBalance(env.coinbase)
		coinbaseDelta := big.NewInt(0).Sub(coinbaseBalanceAfter, coinbaseBalanceBefore)
		coinbaseDelta.Sub(coinbaseDelta, gasFeesTx)
		ethSentToCoinbase.Add(ethSentToCoinbase, coinbaseDelta)

		// NOTE - it differs from prod!, if changed - change in commit bundle too
		//if !txInPendingPool {
		//	// If tx is not in pending pool, count the gas fees
		//	gasFees.Add(gasFees, gasFeesTx)
		//}
		gasFees.Add(gasFees, gasFeesTx)
	}

	totalEth := new(big.Int).Add(ethSentToCoinbase, gasFees)

	return types.SimulatedBundle{
		MevGasPrice:       new(big.Int).Div(totalEth, new(big.Int).SetUint64(totalGasUsed)),
		TotalEth:          totalEth,
		EthSentToCoinbase: ethSentToCoinbase,
		TotalGasUsed:      totalGasUsed,
		OriginalBundle:    bundle,
	}, nil
}

func (sig signerList) signTx(i int, gas uint64, gasTipCap *big.Int, gasFeeCap *big.Int, to common.Address, value *big.Int, data []byte) *types.Transaction {
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

func genGenesisAlloc(sign signerList, contractAddr []common.Address, contractCode [][]byte) core.GenesisAlloc {
	genesisAlloc := make(core.GenesisAlloc)
	for i := 0; i < len(sign.signers); i++ {
		genesisAlloc[sign.addresses[i]] = core.GenesisAccount{
			Balance: big.NewInt(1000000000000000000), // 1 ether
			Nonce:   sign.nonces[i],
		}
	}

	for i, address := range contractAddr {
		genesisAlloc[address] = core.GenesisAccount{
			Balance: new(big.Int),
			Code:    contractCode[i],
		}
	}

	return genesisAlloc
}

func genTestSetup() (*state.StateDB, chainData, signerList) {
	config := params.AllEthashProtocolChanges
	signerList := genSignerList(10, params.AllEthashProtocolChanges)
	genesisAlloc := genGenesisAlloc(signerList, []common.Address{payProxyAddress, logContractAddress}, [][]byte{payProxyCode, logContractCode})

	stateDB, chainData := genTestSetupWithAlloc(config, genesisAlloc)
	return stateDB, chainData, signerList
}

func genTestSetupWithAlloc(config *params.ChainConfig, alloc core.GenesisAlloc) (*state.StateDB, chainData) {
	db := rawdb.NewMemoryDatabase()

	gspec := &core.Genesis{
		Config: config,
		Alloc:  alloc,
	}
	_ = gspec.MustCommit(db)

	chain, _ := core.NewBlockChain(db, &core.CacheConfig{TrieDirtyDisabled: true}, gspec, nil, ethash.NewFaker(), vm.Config{}, nil, nil)

	stateDB, _ := state.New(chain.CurrentHeader().Root, state.NewDatabase(db), nil)

	return stateDB, chainData{config, chain, nil}
}

func newEnvironment(data chainData, state *state.StateDB, coinbase common.Address, gasLimit uint64, baseFee *big.Int) *environment {
	currentBlock := data.chain.CurrentBlock()
	// Note the passed coinbase may be different with header.Coinbase.
	return &environment{
		signer:    types.MakeSigner(data.chainConfig, currentBlock.Number),
		state:     state,
		gasPool:   new(core.GasPool).AddGas(gasLimit),
		coinbase:  coinbase,
		ancestors: mapset.NewSet[common.Hash](),
		family:    mapset.NewSet[common.Hash](),
		header: &types.Header{
			Coinbase:   coinbase,
			ParentHash: currentBlock.Hash(),
			Number:     new(big.Int).Add(currentBlock.Number, big.NewInt(1)),
			GasLimit:   gasLimit,
			GasUsed:    0,
			BaseFee:    baseFee,
			Difficulty: big.NewInt(0),
		},
		uncles: make(map[common.Hash]*types.Header),
		profit: new(big.Int),
	}
}

func TestTxCommit(t *testing.T) {
	statedb, chData, signers := genTestSetup()

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
	statedb, chData, signers := genTestSetup()

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
	statedb, chData, signers := genTestSetup()

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
	statedb, chData, signers := genTestSetup()

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
	statedb, chData, signers := genTestSetup()

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
	newProfitBefore := new(big.Int).Set(envDiff.newProfit)
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
	statedb, chData, signers := genTestSetup()

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

	for _, algoType := range []AlgoType{ALGO_MEV_GETH, ALGO_GREEDY, ALGO_GREEDY_BUCKETS} {
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

	for _, algoType := range []AlgoType{ALGO_GREEDY, ALGO_GREEDY_BUCKETS} {
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

	statedb, chData, signers := genTestSetup()

	env := newEnvironment(chData, statedb, signers.addresses[0], GasLimit, big.NewInt(1))

	// Sending payment to the plain EOA
	gas, isEOA, err := estimatePayoutTxGas(env, signers.addresses[1], signers.addresses[2], signers.signers[1], chData)
	require.Equal(t, uint64(21000), gas)
	require.True(t, isEOA)
	require.NoError(t, err)

	expectedPayment := new(big.Int).Sub(availableFunds, big.NewInt(21000))
	balanceBefore := env.state.GetBalance(signers.addresses[2])
	rec, err := insertPayoutTx(env, signers.addresses[1], signers.addresses[2], gas, isEOA, availableFunds, signers.signers[1], chData)
	balanceAfter := env.state.GetBalance(signers.addresses[2])
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
	balanceBefore = env.state.GetBalance(logContractAddress)
	rec, err = insertPayoutTx(env, signers.addresses[1], logContractAddress, gas, isEOA, availableFunds, signers.signers[1], chData)
	balanceAfter = env.state.GetBalance(logContractAddress)
	require.NoError(t, err)
	require.NotNil(t, rec)
	require.Equal(t, types.ReceiptStatusSuccessful, rec.Status)
	require.Equal(t, uint64(22025), rec.GasUsed)
	require.True(t, new(big.Int).Sub(balanceAfter, balanceBefore).Cmp(expectedPayment) == 0)
	require.Equal(t, env.state.GetNonce(signers.addresses[1]), uint64(2))

	// Try requesting less gas for contract tx. We request 21k gas, but we must pay 22025
	expectedPayment = new(big.Int).Sub(availableFunds, big.NewInt(22025))
	balanceBefore = env.state.GetBalance(logContractAddress)
	rec, err = insertPayoutTx(env, signers.addresses[1], logContractAddress, 21000, isEOA, availableFunds, signers.signers[1], chData)
	balanceAfter = env.state.GetBalance(logContractAddress)
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

const (
	Baseline       = 0
	SingleSnapshot = 1
	MultiSnapshot  = 2
)

type stateComparisonTestContext struct {
	Name string

	statedb   *state.StateDB
	chainData chainData
	signers   signerList

	env *environment

	envDiff *environmentDiff
	changes *envChanges

	transactions []*types.Transaction

	rootHash common.Hash
}

type stateComparisonTestContexts []stateComparisonTestContext

func (sc stateComparisonTestContexts) ValidateRootHashes(t *testing.T, expected common.Hash) {
	for _, tc := range sc {
		require.Equal(t, expected.Bytes(), tc.rootHash.Bytes(),
			"root hash mismatch for test context %s [expected: %s] [found: %s]",
			tc.Name, expected.TerminalString(), tc.rootHash.TerminalString())
	}
}

func (sc stateComparisonTestContexts) GenerateTransactions(t *testing.T, txCount int, failEveryN int) {
	for tcIndex, tc := range sc {
		signers := tc.signers
		tc.transactions = sc.generateTransactions(txCount, failEveryN, signers)
		tc.signers = signers
		require.Len(t, tc.transactions, txCount)

		sc[tcIndex] = tc
	}
}

func (sc stateComparisonTestContexts) generateTransactions(txCount int, failEveryN int, signers signerList) []*types.Transaction {
	transactions := make([]*types.Transaction, 0, txCount)
	for i := 0; i < txCount; i++ {
		var data []byte
		if failEveryN != 0 && i%failEveryN == 0 {
			data = []byte{0x01}
		} else {
			data = []byte{}
		}

		from := i % len(signers.addresses)
		tx := signers.signTx(from, params.TxGas, big.NewInt(0), big.NewInt(1),
			signers.addresses[(i+1)%len(signers.addresses)], big.NewInt(0), data)
		transactions = append(transactions, tx)
	}

	return transactions
}

func (sc stateComparisonTestContexts) UpdateRootHashes(t *testing.T) {
	for tcIndex, tc := range sc {
		if tc.envDiff != nil {
			tc.rootHash = tc.envDiff.baseEnvironment.state.IntermediateRoot(true)
		} else {
			tc.rootHash = tc.env.state.IntermediateRoot(true)
		}
		sc[tcIndex] = tc

		require.NotEmpty(t, tc.rootHash.Bytes(), "root hash is empty for test context %s", tc.Name)
	}
}

func (sc stateComparisonTestContexts) ValidateTestCases(t *testing.T, reference int) {
	expected := sc[reference]
	var (
		expectedGasPool      *core.GasPool        = expected.envDiff.baseEnvironment.gasPool
		expectedHeader       *types.Header        = expected.envDiff.baseEnvironment.header
		expectedProfit       *big.Int             = expected.envDiff.baseEnvironment.profit
		expectedTxCount      int                  = expected.envDiff.baseEnvironment.tcount
		expectedTransactions []*types.Transaction = expected.envDiff.baseEnvironment.txs
		expectedReceipts     types.Receipts       = expected.envDiff.baseEnvironment.receipts
	)
	for tcIndex, tc := range sc {
		if tcIndex == reference {
			continue
		}

		var (
			actualGasPool      *core.GasPool        = tc.env.gasPool
			actualHeader       *types.Header        = tc.env.header
			actualProfit       *big.Int             = tc.env.profit
			actualTxCount      int                  = tc.env.tcount
			actualTransactions []*types.Transaction = tc.env.txs
			actualReceipts     types.Receipts       = tc.env.receipts
		)
		if actualGasPool.Gas() != expectedGasPool.Gas() {
			t.Errorf("gas pool mismatch for test context %s [expected: %d] [found: %d]",
				tc.Name, expectedGasPool.Gas(), actualGasPool.Gas())
		}

		if actualHeader.Hash() != expectedHeader.Hash() {
			t.Errorf("header hash mismatch for test context %s [expected: %s] [found: %s]",
				tc.Name, expectedHeader.Hash().TerminalString(), actualHeader.Hash().TerminalString())
		}

		if actualProfit.Cmp(expectedProfit) != 0 {
			t.Errorf("profit mismatch for test context %s [expected: %d] [found: %d]",
				tc.Name, expectedProfit, actualProfit)
		}

		if actualTxCount != expectedTxCount {
			t.Errorf("transaction count mismatch for test context %s [expected: %d] [found: %d]",
				tc.Name, expectedTxCount, actualTxCount)
			break
		}

		if len(actualTransactions) != len(expectedTransactions) {
			t.Errorf("transaction count mismatch for test context %s [expected: %d] [found: %d]",
				tc.Name, len(expectedTransactions), len(actualTransactions))
		}

		for txIdx := 0; txIdx < len(actualTransactions); txIdx++ {
			expectedTx := expectedTransactions[txIdx]
			actualTx := actualTransactions[txIdx]

			expectedBytes, err := rlp.EncodeToBytes(expectedTx)
			if err != nil {
				t.Fatalf("failed to encode expected transaction #%d: %v", txIdx, err)
			}

			actualBytes, err := rlp.EncodeToBytes(actualTx)
			if err != nil {
				t.Fatalf("failed to encode actual transaction #%d: %v", txIdx, err)
			}

			if !bytes.Equal(expectedBytes, actualBytes) {
				t.Errorf("transaction #%d mismatch for test context %s [expected: %v] [found: %v]",
					txIdx, tc.Name, expectedTx, actualTx)
			}
		}

		if len(actualReceipts) != len(expectedReceipts) {
			t.Errorf("receipt count mismatch for test context %s [expected: %d] [found: %d]",
				tc.Name, len(expectedReceipts), len(actualReceipts))
		}
	}
}

func (sc stateComparisonTestContexts) Init(t *testing.T) stateComparisonTestContexts {
	for i := range sc {
		tc := stateComparisonTestContext{}
		tc.statedb, tc.chainData, tc.signers = genTestSetup()
		tc.env = newEnvironment(tc.chainData, tc.statedb, tc.signers.addresses[0], GasLimit, big.NewInt(1))
		var err error
		switch i {
		case Baseline:
			tc.Name = "baseline"
			tc.envDiff = newEnvironmentDiff(tc.env)
		case SingleSnapshot:
			tc.Name = "single-snapshot"
			tc.changes, err = newEnvChanges(tc.env)
			_ = tc.changes.env.state.MultiTxSnapshotCommit()
		case MultiSnapshot:
			tc.Name = "multi-snapshot"
			tc.changes, err = newEnvChanges(tc.env)
			_ = tc.changes.env.state.MultiTxSnapshotCommit()
		}

		require.NoError(t, err, "failed to initialize test contexts: %v", err)
		sc[i] = tc
	}
	return sc
}

func TestStateComparisons(t *testing.T) {
	var testContexts = make(stateComparisonTestContexts, 3)

	// test commit tx
	t.Run("state-compare-commit-tx", func(t *testing.T) {
		testContexts = testContexts.Init(t)
		for i := 0; i < 3; i++ {
			tx1 := testContexts[i].signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1),
				testContexts[i].signers.addresses[2], big.NewInt(0), []byte{})
			var (
				receipt *types.Receipt
				status  int
				err     error
			)
			switch i {
			case Baseline:
				receipt, status, err = testContexts[i].envDiff.commitTx(tx1, testContexts[i].chainData)
				testContexts[i].envDiff.applyToBaseEnv()

			case SingleSnapshot:
				require.NoError(t, testContexts[i].changes.env.state.NewMultiTxSnapshot(), "can't create multi tx snapshot: %v", err)
				receipt, status, err = testContexts[i].changes.commitTx(tx1, testContexts[i].chainData)
				require.NoError(t, err, "can't commit single snapshot tx")

				err = testContexts[i].changes.apply()
			case MultiSnapshot:
				require.NoError(t, testContexts[i].changes.env.state.NewMultiTxSnapshot(), "can't create multi tx snapshot: %v", err)
				receipt, status, err = testContexts[i].changes.commitTx(tx1, testContexts[i].chainData)
				require.NoError(t, err, "can't commit multi snapshot tx")

				err = testContexts[i].changes.apply()
			}
			require.NoError(t, err, "can't commit tx")
			require.Equal(t, types.ReceiptStatusSuccessful, receipt.Status)
			require.Equal(t, 21000, int(receipt.GasUsed))
			require.Equal(t, shiftTx, status)
		}

		testContexts.UpdateRootHashes(t)
		testContexts.ValidateTestCases(t, Baseline)
		testContexts.ValidateRootHashes(t, testContexts[Baseline].rootHash)
	})

	// test bundle
	t.Run("state-compare-bundle", func(t *testing.T) {
		testContexts = testContexts.Init(t)
		for i, tc := range testContexts {
			var (
				signers = tc.signers
				header  = tc.env.header
				env     = tc.env
				chData  = tc.chainData
			)

			tx1 := signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{})
			tx2 := signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{})

			mevBundle := types.MevBundle{
				Txs:         types.Transactions{tx1, tx2},
				BlockNumber: header.Number,
			}

			simBundle, err := simulateBundle(env, mevBundle, chData, nil)
			require.NoError(t, err, "can't simulate bundle: %v", err)

			switch i {
			case Baseline:
				err = tc.envDiff.commitBundle(&simBundle, chData, nil, defaultAlgorithmConfig)
				if err != nil {
					break
				}
				tc.envDiff.applyToBaseEnv()

			case SingleSnapshot:
				err = tc.changes.env.state.NewMultiTxSnapshot()
				require.NoError(t, err, "can't create multi tx snapshot: %v", err)

				err = tc.changes.commitBundle(&simBundle, chData, defaultAlgorithmConfig)
				if err != nil {
					break
				}

				err = tc.changes.apply()

			case MultiSnapshot:
				err = tc.changes.env.state.NewMultiTxSnapshot()
				require.NoError(t, err, "can't create multi tx snapshot: %v", err)

				err = tc.changes.commitBundle(&simBundle, chData, defaultAlgorithmConfig)
				if err != nil {
					break
				}

				err = tc.changes.apply()
			}

			require.NoError(t, err, "can't commit bundle: %v", err)
		}

		testContexts.UpdateRootHashes(t)
		testContexts.ValidateTestCases(t, 0)
		testContexts.ValidateRootHashes(t, testContexts[Baseline].rootHash)
	})

	// test failed transactions
	t.Run("state-compare-failed-txs", func(t *testing.T) {
		// generate 100 transactions, with 50% of them failing
		var (
			txCount    = 100
			failEveryN = 2
		)
		testContexts = testContexts.Init(t)
		testContexts.GenerateTransactions(t, txCount, failEveryN)
		require.Len(t, testContexts[Baseline].transactions, txCount)

		for txIdx := 0; txIdx < txCount; txIdx++ {
			for ctxIdx, tc := range testContexts {
				tx := tc.transactions[txIdx]

				var commitErr error
				switch ctxIdx {
				case Baseline:
					_, _, commitErr = tc.envDiff.commitTx(tx, tc.chainData)
					tc.envDiff.applyToBaseEnv()

				case SingleSnapshot:
					err := tc.changes.env.state.NewMultiTxSnapshot()
					require.NoError(t, err, "can't create multi tx snapshot for tx %d: %v", txIdx, err)

					_, _, commitErr = tc.changes.commitTx(tx, tc.chainData)
					require.NoError(t, tc.changes.apply())
				case MultiSnapshot:
					err := tc.changes.env.state.NewMultiTxSnapshot()
					require.NoError(t, err,
						"can't create multi tx snapshot: %v", err)

					err = tc.changes.env.state.NewMultiTxSnapshot()
					require.NoError(t, err,
						"can't create multi tx snapshot: %v", err)

					_, _, commitErr = tc.changes.commitTx(tx, tc.chainData)
					require.NoError(t, tc.changes.apply())

					// NOTE(wazzymandias): At the time of writing this, the changes struct does not reset after performing
					// an apply - because the intended use of the changes struct is to create it and discard it
					// after every commit->(discard||apply) loop.
					// So for now to test multiple snapshots we apply the changes for the top of the stack and
					// then pop the underlying state snapshot from the base of the stack.
					// Otherwise, if changes are applied twice, then there can be double counting of transactions.
					require.NoError(t, tc.changes.env.state.MultiTxSnapshotCommit())
				}

				if txIdx%failEveryN == 0 {
					require.Errorf(t, commitErr, "tx %d should fail", txIdx)
				} else {
					require.NoError(t, commitErr, "tx %d should succeed, found: %v", txIdx, commitErr)
				}
			}
		}
		testContexts.UpdateRootHashes(t)
		testContexts.ValidateTestCases(t, 0)
		testContexts.ValidateRootHashes(t, testContexts[Baseline].rootHash)
	})
}
