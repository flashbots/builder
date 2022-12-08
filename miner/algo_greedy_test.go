package miner

import (
	"crypto/ecdsa"
	"crypto/rand"
	"embed"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
)

func TestBuildBlockGasLimit(t *testing.T) {
	statedb, chData, signers := genTestSetup()

	env := newEnvironment(chData, statedb, signers.addresses[0], 21000, big.NewInt(1))

	txs := make(map[common.Address]types.Transactions)

	txs[signers.addresses[1]] = types.Transactions{
		signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{}),
	}
	txs[signers.addresses[2]] = types.Transactions{
		signers.signTx(2, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{}),
	}

	builder := newGreedyBuilder(chData.chain, chData.chainConfig, nil, env, nil, nil)

	result, _ := builder.buildBlock([]types.SimulatedBundle{}, txs)
	log.Info("block built", "txs", len(result.txs), "gasPool", result.gasPool.Gas())
	if result.tcount != 1 {
		t.Fatal("Incorrect tx count")
	}
}

func TestTxWithMinerFeeHeap(t *testing.T) {
	statedb, chData, signers := genTestSetup()

	env := newEnvironment(chData, statedb, signers.addresses[0], 21000, big.NewInt(1))

	txs := make(map[common.Address]types.Transactions)

	txs[signers.addresses[1]] = types.Transactions{
		signers.signTx(1, 21000, big.NewInt(1), big.NewInt(5), signers.addresses[2], big.NewInt(0), []byte{}),
	}
	txs[signers.addresses[2]] = types.Transactions{
		signers.signTx(2, 21000, big.NewInt(4), big.NewInt(5), signers.addresses[2], big.NewInt(0), []byte{}),
	}

	bundle1 := types.SimulatedBundle{MevGasPrice: big.NewInt(3), OriginalBundle: types.MevBundle{Hash: common.HexToHash("0xb1")}}
	bundle2 := types.SimulatedBundle{MevGasPrice: big.NewInt(2), OriginalBundle: types.MevBundle{Hash: common.HexToHash("0xb2")}}

	orders := types.NewTransactionsByPriceAndNonce(env.signer, txs, []types.SimulatedBundle{bundle2, bundle1}, env.header.BaseFee)

	for {
		order := orders.Peek()
		if order == nil {
			return
		}

		if order.Tx() != nil {
			fmt.Println("tx", order.Tx().Hash())
			orders.Shift()
		} else if order.Bundle() != nil {
			fmt.Println("bundle", order.Bundle().OriginalBundle.Hash)
			orders.Pop()
		}
	}
}

var (
	//go:embed testdata
	testdata embed.FS

	// Contract src: https://github.com/zeroXbrock/mev-flood/blob/main/contracts/lottery_mev.sol
	lotteryABI  = mustReadABI(testdata, "testdata/lottery_mev.abi.json")
	lotteryCode = mustReadBin(testdata, "testdata/lottery_mev.runtime-bin")

	// Contract src: https://github.com/zeroXbrock/mev-flood/blob/main/contracts/atomic_lottery.sol
	atomicLotteryABI  = mustReadABI(testdata, "testdata/atomic_lottery.abi.json")
	atomicLotteryCode = mustReadBin(testdata, "testdata/atomic_lottery.bin")

	bidInput, _   = lotteryABI.Methods["bid"].Inputs.Pack()
	claimInput, _ = lotteryABI.Methods["claim"].Inputs.Pack()
)

func TestGreedyBuilderBuildBlock(t *testing.T) {
	tests := []struct {
		NLotteries     int
		NBundles       int
		NTxs           int
		BundleGasPrice *big.Int
		TxGasPrice     *big.Int

		WantTxCount int
	}{
		{NLotteries: 1, NBundles: 0, NTxs: 1, BundleGasPrice: big.NewInt(10), TxGasPrice: big.NewInt(1), WantTxCount: 2},
		{NLotteries: 1, NBundles: 1, NTxs: 1, BundleGasPrice: big.NewInt(10), TxGasPrice: big.NewInt(1), WantTxCount: 3},

		{NLotteries: 10, NBundles: 1, NTxs: 1, BundleGasPrice: big.NewInt(10), TxGasPrice: big.NewInt(1), WantTxCount: 12},
		{NLotteries: 10, NBundles: 10, NTxs: 1, BundleGasPrice: big.NewInt(10), TxGasPrice: big.NewInt(1), WantTxCount: 12},
		{NLotteries: 10, NBundles: 10, NTxs: 10, BundleGasPrice: big.NewInt(10), TxGasPrice: big.NewInt(1), WantTxCount: 30},
		{NLotteries: 10, NBundles: 1, NTxs: 10, BundleGasPrice: big.NewInt(10), TxGasPrice: big.NewInt(1), WantTxCount: 30},

		// Mempool txs with higher gas price than bundles
		{NLotteries: 1, NBundles: 1, NTxs: 1, BundleGasPrice: big.NewInt(1), TxGasPrice: big.NewInt(10), WantTxCount: 2},
	}

	for i, test := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			var (
				config                  = params.AllEthashProtocolChanges
				signer                  = types.LatestSigner(config)
				alloc, addrs, lotteries = genLotteryGenesisAlloc(test.NBundles+test.NTxs, test.NLotteries)
				statedb, chData         = genTestSetupWithAlloc(config, alloc)
				coinbase                = randAddr()
				blockGasLimit           = uint64(15_000_000)
				env                     = newEnvironment(chData, statedb, coinbase, blockGasLimit, big.NewInt(0))
				builder                 = newGreedyBuilder(chData.chain, chData.chainConfig, nil, env, nil, nil)

				txPool  = make(map[common.Address]types.Transactions)
				bundles = make([]types.SimulatedBundle, 0)
			)

			for i, addr := range addrs {
				key, _ := crypto.ToECDSA(alloc[addr].PrivateKey)

				if i < test.NBundles {
					// build MEV bundle
					//
					// bundle contains NLotteries transactions, one to each lottery.
					var txs types.Transactions
					for j, lottery := range lotteries {
						tx := types.MustSignNewTx(key, signer, &types.LegacyTx{
							Nonce:    uint64(j),
							Gas:      200_000,
							Value:    big.NewInt(1),
							GasPrice: test.BundleGasPrice,
							Data:     append(atomicLotteryCode, mustPack(atomicLotteryABI, "", lottery)...),
						})
						txs = append(txs, tx)
					}
					bundle, err := simulateBundle(env, types.MevBundle{Txs: txs, BlockNumber: big.NewInt(0)}, chData, nil)
					if err != nil {
						t.Fatalf("Failed to simulate bundle: %v", err)
					}
					bundles = append(bundles, bundle)
				} else {
					// build regular tx
					//
					// tx0: lottery.bid()
					// tx1: lottery.claim()
					tx0 := types.MustSignNewTx(key, signer, &types.LegacyTx{
						To:       &lotteries[i%len(lotteries)],
						Nonce:    0,
						Gas:      100_000,
						Value:    big.NewInt(1),
						GasPrice: test.TxGasPrice,
						Data:     bidInput,
					})
					tx1 := types.MustSignNewTx(key, signer, &types.LegacyTx{
						To:       &lotteries[i%len(lotteries)],
						Nonce:    1,
						Gas:      100_000,
						Value:    big.NewInt(1),
						GasPrice: test.TxGasPrice,
						Data:     claimInput,
					})
					txPool[addr] = types.Transactions{tx0, tx1}
				}
			}

			// build block
			result, includedBundles := builder.buildBlock(bundles, txPool)
			if test.WantTxCount != result.tcount {
				t.Fatalf("TxCount: want %v, got %v", test.WantTxCount, result.tcount)
			}

			// wantProfit calculation:
			//
			// each tx has a gasPrice of "txGasPrice" wei
			// each bundle has a gasPrice of "bundleGasPrice" wei
			// thus, profit = (blockGasUsed - bundleGasUsed) * txGasPrice + bundleGasUsed * bundleGasPrice
			blockGasUsed := blockGasLimit - uint64(*result.gasPool)
			var bundleGasUsed uint64
			for _, bundle := range includedBundles {
				bundleGasUsed += bundle.TotalGasUsed
			}

			wantProfit := new(big.Int).Add(
				new(big.Int).Mul(new(big.Int).SetUint64(blockGasUsed-bundleGasUsed), test.TxGasPrice),
				new(big.Int).Mul(new(big.Int).SetUint64(bundleGasUsed), test.BundleGasPrice),
			)
			if wantProfit.Cmp(result.profit) != 0 {
				t.Fatalf("Profit: want %v, got %v", wantProfit, result.profit)
			}
		})
	}
}

func genLotteryGenesisAlloc(nAccs, nLotteries int) (core.GenesisAlloc, []common.Address, []common.Address) {
	alloc := make(core.GenesisAlloc, nAccs+nLotteries)

	// create nAccs accounts with a balance of 1 eth each
	addrs := make([]common.Address, nAccs)
	for i := 0; i < nAccs; i++ {
		key := randKey()
		addr := crypto.PubkeyToAddress(key.PublicKey)
		addrs[i] = addr

		alloc[addr] = core.GenesisAccount{
			Balance:    bigEther,
			PrivateKey: crypto.FromECDSA(key),
		}
	}

	// create nLotteries lottery contracts with a balance of 1 eth each
	lotteries := make([]common.Address, nLotteries)
	for i := 0; i < nLotteries; i++ {
		addr := randAddr()
		lotteries[i] = addr
		alloc[addr] = core.GenesisAccount{
			Balance: bigEther,
			Code:    lotteryCode,
		}
	}

	return alloc, addrs, lotteries
}

// randAddr returns a random address.
func randAddr() (addr common.Address) {
	rand.Read(addr[:])
	return addr
}

// randKey returns a random private key or panics on error.
func randKey() *ecdsa.PrivateKey {
	key, err := crypto.GenerateKey()
	if err != nil {
		panic(err)
	}
	return key
}

// mustRead reads the file with the given path in the given filesystem or panics
// on error.
func mustRead(fs embed.FS, path string) []byte {
	f, err := fs.Open(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		panic(err)
	}
	return data
}

// mustReadBin reads a hex encoded contract from the file with the given path in
// the given filesystem or panics on error.
func mustReadBin(fs embed.FS, path string) []byte {
	data := mustRead(fs, path)
	dataStr := strings.TrimSpace(string(data))
	if l := len(dataStr); l%2 != 0 {
		panic(fmt.Sprintf("invalid hex string length: %d", l))
	}

	return common.FromHex(dataStr)
}

// mustReadABI reads the ABI definition form the file with the given path in the
// given filesystem or panics on error.
func mustReadABI(fs embed.FS, path string) *abi.ABI {
	data := mustRead(fs, path)
	abi := new(abi.ABI)
	if err := abi.UnmarshalJSON(data); err != nil {
		panic(err)
	}
	return abi
}

// mustPack encodes the method with the given name and arguments or panics on
// error.
func mustPack(abi *abi.ABI, name string, args ...any) []byte {
	input, err := abi.Pack(name, args...)
	if err != nil {
		panic(err)
	}
	return input
}
