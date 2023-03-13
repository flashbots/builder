package miner

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"math/big"
	"math/rand"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethmath "github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

var (
	wethAddress           = common.HexToAddress("0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512")
	daiAddress            = common.HexToAddress("0x5FbDB2315678afecb367f032d93F642f64180aa3")
	univ2FactoryA_Address = common.HexToAddress("0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0")
	univ2FactoryB_Address = common.HexToAddress("0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9")
	atomicSwapAddress     = common.HexToAddress("0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9")

	bigEther = big.NewInt(params.Ether)
)

func enableLogging() {
	log.Root().SetHandler(log.LvlFilterHandler(log.LvlDebug, log.StreamHandler(os.Stderr, log.TerminalFormat(true))))
}

func deployAllContracts(t *testing.T, key *ecdsa.PrivateKey, gasPrice *big.Int) []*types.Transaction {
	allContractsData, err := os.ReadFile("testdata/allcontracts.signeddata")
	require.NoError(t, err)

	var signedTxsBytes []hexutil.Bytes
	err = json.Unmarshal(allContractsData, &signedTxsBytes)
	require.NoError(t, err)

	var signedTxs []*types.Transaction
	for _, signedTxBytes := range signedTxsBytes {
		signedTx := types.Transaction{}
		err = signedTx.UnmarshalBinary(signedTxBytes)
		require.NoError(t, err)
		signedTxs = append(signedTxs, &signedTx)
	}

	return signedTxs
}

type TestParticipant struct {
	key     *ecdsa.PrivateKey
	address common.Address
}

func NewParticipant() TestParticipant {
	pk, _ := crypto.GenerateKey()
	address := crypto.PubkeyToAddress(pk.PublicKey)
	return TestParticipant{pk, address}
}

type TestParticipants struct {
	searchers []TestParticipant
	users     []TestParticipant
}

func NewTestParticipants(nSearchers int, nUsers int) TestParticipants {
	opa := TestParticipants{}

	for i := 0; i < nSearchers; i++ {
		opa.searchers = append(opa.searchers, NewParticipant())
	}

	for i := 0; i < nUsers; i++ {
		opa.users = append(opa.users, NewParticipant())
	}

	return opa
}

func (o *TestParticipants) AppendToGenesisAlloc(genesis core.GenesisAlloc) core.GenesisAlloc {
	for _, searcher := range o.searchers {
		genesis[searcher.address] = core.GenesisAccount{Balance: new(big.Int).Mul(big.NewInt(10000), bigEther)}
	}

	for _, user := range o.users {
		genesis[user.address] = core.GenesisAccount{Balance: new(big.Int).Mul(big.NewInt(10000), bigEther)}
	}

	return genesis
}

func parseAbi(t *testing.T, filename string) *abi.ABI {
	abiData, err := os.ReadFile(filename)
	require.NoError(t, err)

	resAbi := new(abi.ABI)
	err = resAbi.UnmarshalJSON(abiData)
	require.NoError(t, err)

	return resAbi
}

func TestSimulatorState(t *testing.T) {
	// enableLogging()

	t.Cleanup(func() {
		testConfig.AlgoType = ALGO_MEV_GETH
		testConfig.BuilderTxSigningKey = nil
		testConfig.Etherbase = common.Address{}
	})

	testConfig.AlgoType = ALGO_GREEDY
	var err error
	testConfig.BuilderTxSigningKey, err = crypto.GenerateKey()
	require.NoError(t, err)
	testConfig.Etherbase = crypto.PubkeyToAddress(testConfig.BuilderTxSigningKey.PublicKey)

	db := rawdb.NewMemoryDatabase()
	chainConfig := *params.AllEthashProtocolChanges
	chainConfig.ChainID = big.NewInt(31337)
	engine := ethash.NewFaker()

	// (not needed I think) chainConfig.LondonBlock = big.NewInt(0)
	deployerKey, err := crypto.ToECDSA(hexutil.MustDecode("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"))
	deployerAddress := crypto.PubkeyToAddress(deployerKey.PublicKey)
	deployerTestAddress := common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	alloc := core.GenesisAlloc{deployerAddress: {Balance: new(big.Int).Mul(big.NewInt(10000), bigEther)}, deployerTestAddress: {Balance: new(big.Int).Mul(big.NewInt(10000), bigEther)}}

	testParticipants := NewTestParticipants(5, 5)
	alloc = testParticipants.AppendToGenesisAlloc(alloc)

	var genesis = core.Genesis{
		Config:   &chainConfig,
		Alloc:    alloc,
		GasLimit: 30000000,
	}

	w, b := newTestWorkerGenesis(t, &chainConfig, engine, db, genesis, 0)
	w.setEtherbase(crypto.PubkeyToAddress(testConfig.BuilderTxSigningKey.PublicKey))

	simBackend := backends.NewSimulatedBackendChain(db, b.chain)

	univ2FactoryA := NewTContract(t, simBackend, "testdata/univ2factory.abi", univ2FactoryA_Address)
	univ2FactoryB := NewTContract(t, simBackend, "testdata/univ2factory.abi", univ2FactoryB_Address)

	wethContract := NewTContract(t, simBackend, "testdata/weth.abi", wethAddress)
	daiContract := NewTContract(t, simBackend, "testdata/dai.abi", daiAddress)
	atomicSwapContract := NewTContract(t, simBackend, "testdata/swap.abi", atomicSwapAddress)

	testAddress1Key, _ := crypto.GenerateKey()
	testAddress1 := crypto.PubkeyToAddress(testAddress1Key.PublicKey)

	rand.Seed(10)

	deploymentTxs := deployAllContracts(t, deployerKey, b.chain.CurrentHeader().BaseFee)

	getBaseFee := func() *big.Int {
		return new(big.Int).Mul(big.NewInt(2), b.chain.CurrentHeader().BaseFee)
	}

	nonceModFor := big.NewInt(0)
	nonceMod := make(map[common.Address]uint64)
	getNonce := func(addr common.Address) uint64 {
		if nonceModFor.Cmp(b.chain.CurrentHeader().Number) != 0 {
			nonceMod = make(map[common.Address]uint64)
			nonceModFor.Set(b.chain.CurrentHeader().Number)
		}

		cm, _ := nonceMod[addr]
		nonceMod[addr] = cm + 1
		return b.txPool.Nonce(addr) + cm
	}

	prepareContractCallTx := func(contract tConctract, signerKey *ecdsa.PrivateKey, method string, args ...interface{}) *types.Transaction {
		callData, err := contract.abi.Pack(method, args...)
		require.NoError(t, err)

		fromAddress := crypto.PubkeyToAddress(signerKey.PublicKey)

		callRes, err := contract.doCall(fromAddress, method, args...)
		if err != nil {
			t.Errorf("Prepared smart contract call error %s with result %s", err.Error(), string(callRes))
		}

		tx, err := types.SignTx(types.NewTransaction(getNonce(fromAddress), contract.address, new(big.Int), 9000000, getBaseFee(), callData), types.HomesteadSigner{}, signerKey)
		require.NoError(t, err)

		return tx
	}

	buildBlock := func(txs []*types.Transaction, requireTx int) *types.Block {
		errs := b.txPool.AddLocals(txs)
		for _, err := range errs {
			require.NoError(t, err)
		}

		block, _, err := w.getSealingBlock(b.chain.CurrentBlock().Hash(), b.chain.CurrentHeader().Time+12, testAddress1, 0, common.Hash{}, nil, false, nil)
		require.NoError(t, err)
		require.NotNil(t, block)
		if requireTx != -1 {
			require.Equal(t, requireTx, len(block.Transactions()))
		}
		_, err = b.chain.InsertChain([]*types.Block{block})
		require.NoError(t, err)
		return block
	}

	buildBlock(deploymentTxs, len(deploymentTxs)+1)
	require.Equal(t, uint64(18), b.txPool.Nonce(deployerAddress))
	require.Equal(t, uint64(3), b.txPool.Nonce(deployerTestAddress))

	// Mint tokens
	require.NoError(t, err)

	approveTxs := []*types.Transaction{}

	adminApproveTxWeth := prepareContractCallTx(wethContract, deployerKey, "approve", atomicSwapContract.address, ethmath.MaxBig256)
	approveTxs = append(approveTxs, adminApproveTxWeth)
	adminApproveTxDai := prepareContractCallTx(daiContract, deployerKey, "approve", atomicSwapContract.address, ethmath.MaxBig256)
	approveTxs = append(approveTxs, adminApproveTxDai)

	for _, spender := range []TestParticipant{testParticipants.users[0], testParticipants.searchers[0]} {

		mintTx := prepareContractCallTx(daiContract, deployerKey, "mint", spender.address, new(big.Int).Mul(bigEther, big.NewInt(50000)))
		approveTxs = append(approveTxs, mintTx)

		depositTx, err := types.SignTx(types.NewTransaction(getNonce(spender.address), wethContract.address, new(big.Int).Mul(bigEther, big.NewInt(1000)), 9000000, getBaseFee(), hexutil.MustDecode("0xd0e30db0")), types.HomesteadSigner{}, spender.key)
		require.NoError(t, err)
		approveTxs = append(approveTxs, depositTx)

		spenderApproveTxWeth := prepareContractCallTx(wethContract, spender.key, "approve", atomicSwapContract.address, ethmath.MaxBig256)
		approveTxs = append(approveTxs, spenderApproveTxWeth)

		spenderApproveTxDai := prepareContractCallTx(daiContract, spender.key, "approve", atomicSwapContract.address, ethmath.MaxBig256)
		approveTxs = append(approveTxs, spenderApproveTxDai)
	}

	buildBlock(approveTxs, len(approveTxs)+1)

	amtIn := new(big.Int).Mul(bigEther, big.NewInt(50))

	userSwapTx := prepareContractCallTx(atomicSwapContract, testParticipants.users[0].key, "swap", []common.Address{wethContract.address, daiContract.address}, amtIn, univ2FactoryA.address, testParticipants.users[0].address, false)

	backrunTxData, err := atomicSwapContract.abi.Pack("backrun", daiContract.address, univ2FactoryB.address, univ2FactoryA.address, new(big.Int).Div(amtIn, big.NewInt(2)))
	require.NoError(t, err)

	backrunTx, err := types.SignTx(types.NewTransaction(getNonce(testParticipants.searchers[0].address), atomicSwapContract.address, new(big.Int), 9000000, getBaseFee(), backrunTxData), types.HomesteadSigner{}, testParticipants.searchers[0].key)

	targetBlockNumber := new(big.Int).Set(b.chain.CurrentHeader().Number)
	targetBlockNumber.Add(targetBlockNumber, big.NewInt(1))
	b.txPool.AddMevBundle(types.Transactions{userSwapTx, backrunTx}, targetBlockNumber, uuid.UUID{}, common.Address{}, 0, 0, nil)
	buildBlock([]*types.Transaction{}, 3)
}

type tConctract struct {
	t          *testing.T
	simBackend *backends.SimulatedBackend
	abi        *abi.ABI
	address    common.Address
}

func NewTContract(t *testing.T, simBackend *backends.SimulatedBackend, abiFile string, address common.Address) tConctract {
	return tConctract{
		t:          t,
		simBackend: simBackend,
		abi:        parseAbi(t, abiFile),
		address:    address,
	}
}

func (c *tConctract) doCall(fromAddress common.Address, method string, args ...interface{}) ([]byte, error) {
	callData, err := c.abi.Pack(method, args...)
	if err != nil {
		return nil, err
	}

	simRes, err := c.simBackend.CallContract(context.Background(), ethereum.CallMsg{
		From:     fromAddress,
		To:       &c.address,
		GasPrice: new(big.Int),
		Data:     callData,
	}, c.simBackend.Blockchain().CurrentHeader().Number)
	if err != nil {
		return nil, err
	}

	return simRes, nil
}
