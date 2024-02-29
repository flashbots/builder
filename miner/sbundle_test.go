package miner

import (
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

var (
	userPrivKey, _     = crypto.HexToECDSA("0e01d2c89a67cb6a9f2a80a081cb2d7fe98ecc9616aa6966d5a896e795c166c3")
	userAddress        = crypto.PubkeyToAddress(userPrivKey.PublicKey)
	searcherPrivKey, _ = crypto.HexToECDSA("0e797e20fcf93833b029079bfb6494ae1334c7dc4a95e3e36c37895c8be81ebf")
	searcherAddress    = crypto.PubkeyToAddress(searcherPrivKey.PublicKey)
	contractAddress    = common.HexToAddress("0xc100000000000000000000000000000000000000")
	// if calldata[0:32] is not zero, revert; otherwise pay all eth to coinbase
	contractCode = common.Hex2Bytes("6000351561000957fe5b600060006000600034416000f1")

	builderPrivKey, _ = crypto.HexToECDSA("b3cf1b5339dc8d82e65ae959c6400fccbc5d90c83f228fdadb8089d00cdeae94")
	builderAddress    = crypto.PubkeyToAddress(builderPrivKey.PublicKey)

	testSuite SBundleTestSuite
)

func genUserTx(nonce uint64, shouldFail bool) *types.Transaction {
	signer := types.LatestSigner(params.TestChainConfig)
	if shouldFail {
		data := types.DynamicFeeTx{
			ChainID:   big.NewInt(1),
			Nonce:     nonce,
			GasTipCap: big.NewInt(params.GWei),
			GasFeeCap: new(big.Int).Add(testSuite.Header.BaseFee, big.NewInt(params.GWei)),
			Gas:       25000,
			To:        &contractAddress,
			Value:     big.NewInt(0),
			Data:      []byte{0x01},
		}
		return types.MustSignNewTx(userPrivKey, signer, &data)
	} else {
		data := types.DynamicFeeTx{
			ChainID:   big.NewInt(1),
			Nonce:     nonce,
			GasTipCap: big.NewInt(params.GWei),
			GasFeeCap: new(big.Int).Add(testSuite.Header.BaseFee, big.NewInt(params.GWei)),
			Gas:       21000,
			To:        &userAddress,
			Value:     big.NewInt(0),
		}
		return types.MustSignNewTx(userPrivKey, signer, &data)
	}
}

func genBackrunTx(nonce uint64) (*types.Transaction, *uint256.Int) {
	data := &types.DynamicFeeTx{
		ChainID:   big.NewInt(1),
		Nonce:     nonce,
		GasTipCap: big.NewInt(params.GWei),
		GasFeeCap: new(big.Int).Add(testSuite.Header.BaseFee, big.NewInt(params.GWei)),
		Gas:       35000,
		To:        &contractAddress,
		Value:     big.NewInt(params.Ether / 10),
	}
	tx := types.MustSignNewTx(searcherPrivKey, types.LatestSigner(params.TestChainConfig), data)
	backrunFeeValue := new(uint256.Int).Mul(uint256.MustFromBig(tx.GasTipCap()), uint256.NewInt(uint64(30342)))
	backrunValue := new(uint256.Int).Add(uint256.MustFromBig(tx.Value()), backrunFeeValue)
	return tx, backrunValue
}

type TestCaseExtractedRefunds struct {
	Value       *hexutil.U256          `json:"value"`
	Percent     int                    `json:"percent"`
	RefundSplit map[common.Address]int `json:"refundSplit,omitempty"`
}

type SBundleTestCase struct {
	Name             string                     `json:"name"`
	Bundle           ethapi.SendMevBundleArgs   `json:"bundle"`
	ShouldFail       bool                       `json:"shouldFail"`
	ExtractedRefunds []TestCaseExtractedRefunds `json:"extractedRefunds,omitempty"`
}

type SBundleTestSuite struct {
	GenesisAlloc types.GenesisAlloc `json:"genesisAlloc"`
	Header       *types.Header      `json:"header"`
	Tests        []SBundleTestCase  `json:"tests"`
}

func generateTests() {
	testSuite.GenesisAlloc = make(types.GenesisAlloc)
	testSuite.GenesisAlloc[userAddress] = types.Account{Balance: big.NewInt(params.Ether)}
	testSuite.GenesisAlloc[searcherAddress] = types.Account{Balance: big.NewInt(params.Ether)}
	testSuite.GenesisAlloc[contractAddress] = types.Account{Balance: new(big.Int), Code: contractCode}
	testSuite.GenesisAlloc[builderAddress] = types.Account{Balance: new(big.Int)}

	testSuite.Header = &types.Header{
		Number:   big.NewInt(1),
		GasLimit: 30_000_000,
		BaseFee:  big.NewInt(200 * params.GWei),
		Coinbase: builderAddress,
	}

	pushSimpleBundleTest()
	pushBundleWithRevertingTx()
	pushBundleWithInvalidTx()
	pushBundleWithRevertingTxThatCanRevert()
	pushBundleWithInvalidTxThatCanRevert()
	pushBackrunOfTx()
	pushBackrunOfBundle()
	pushBackrunOfBundleWithRefundConfig()
	pushDoubleBackrunOfBundleWithRefundConfig()

	if os.Getenv("DUMP_SBUNDLE_TEST_PATH") != "" {
		jsonBytes, err := json.MarshalIndent(testSuite, "", "  ")
		if err != nil {
			panic(err)
		}
		err = os.WriteFile(os.Getenv("DUMP_SBUNDLE_TEST_PATH"), jsonBytes, 0o644)
		if err != nil {
			panic(err)
		}
	}
}

func pushSBundleTestCase(name string, bundle *types.SBundle, shouldFail bool, refunds []TestCaseExtractedRefunds) {
	args, err := ethapi.ConvertSBundleToArgs(bundle)
	if err != nil {
		panic(err)
	}
	testSuite.Tests = append(testSuite.Tests, SBundleTestCase{
		Name:             name,
		Bundle:           args,
		ShouldFail:       shouldFail,
		ExtractedRefunds: refunds,
	})
}

func pushSimpleBundleTest() {
	// Bundle with 1 tx that should succeed
	bundle := &types.SBundle{
		Inclusion: types.BundleInclusion{
			BlockNumber:    testSuite.Header.Number.Uint64(),
			MaxBlockNumber: testSuite.Header.Number.Uint64(),
		},
		Body: []types.BundleBody{
			{
				Tx: genUserTx(0, false),
			},
		},
	}
	pushSBundleTestCase("simple bundle", bundle, false, nil)
}

func pushBundleWithRevertingTx() {
	// bundle with 2 txs, one that reverts and one that succeeds
	bundle := &types.SBundle{
		Inclusion: types.BundleInclusion{
			BlockNumber:    testSuite.Header.Number.Uint64(),
			MaxBlockNumber: testSuite.Header.Number.Uint64(),
		},
		Body: []types.BundleBody{
			{
				Tx: genUserTx(0, false),
			},
			{
				Tx: genUserTx(1, true),
			},
		},
	}
	pushSBundleTestCase("bundle with reverting tx", bundle, true, nil)
}

func pushBundleWithInvalidTx() {
	bundle := &types.SBundle{
		Inclusion: types.BundleInclusion{
			BlockNumber:    testSuite.Header.Number.Uint64(),
			MaxBlockNumber: testSuite.Header.Number.Uint64(),
		},
		Body: []types.BundleBody{
			{
				Tx: genUserTx(0, false),
			},
			{
				Tx: genUserTx(0, false),
			},
		},
	}
	pushSBundleTestCase("bundle with invalid tx (nonce mismatch)", bundle, true, nil)
}

func pushBundleWithRevertingTxThatCanRevert() {
	bundle := &types.SBundle{
		Inclusion: types.BundleInclusion{
			BlockNumber:    testSuite.Header.Number.Uint64(),
			MaxBlockNumber: testSuite.Header.Number.Uint64(),
		},
		Body: []types.BundleBody{
			{
				Tx: genUserTx(0, false),
			},
			{
				Tx:        genUserTx(1, true),
				CanRevert: true,
			},
		},
	}
	pushSBundleTestCase("bundle with reverting tx that is allowed to revert", bundle, false, nil)
}

func pushBundleWithInvalidTxThatCanRevert() {
	bundle := &types.SBundle{
		Inclusion: types.BundleInclusion{
			BlockNumber:    testSuite.Header.Number.Uint64(),
			MaxBlockNumber: testSuite.Header.Number.Uint64(),
		},
		Body: []types.BundleBody{
			{
				Tx: genUserTx(0, false),
			},
			{
				Tx:        genUserTx(0, false),
				CanRevert: true,
			},
		},
	}
	pushSBundleTestCase("bundle with invalid tx (nonce mismatch) that is allowed to revert", bundle, true, nil)
}

func pushBackrunOfTx() {
	backrun, backrunValue := genBackrunTx(0)
	bundle := &types.SBundle{
		Inclusion: types.BundleInclusion{
			BlockNumber:    testSuite.Header.Number.Uint64(),
			MaxBlockNumber: testSuite.Header.Number.Uint64(),
		},
		Body: []types.BundleBody{
			{
				Tx: genUserTx(0, false),
			},
			{
				Tx: backrun,
			},
		},
		Validity: types.BundleValidity{
			Refund: []types.RefundConstraint{
				{BodyIdx: 0, Percent: 90},
			},
		},
	}
	expectedRefunds := []TestCaseExtractedRefunds{
		{
			Value:   (*hexutil.U256)(backrunValue),
			Percent: 90,
			RefundSplit: map[common.Address]int{
				userAddress: 100,
			},
		},
	}
	pushSBundleTestCase("bundle with backrun of tx", bundle, false, expectedRefunds)
}

func pushBackrunOfBundle() {
	userBundle := &types.SBundle{
		Inclusion: types.BundleInclusion{
			BlockNumber:    testSuite.Header.Number.Uint64(),
			MaxBlockNumber: testSuite.Header.Number.Uint64(),
		},
		Body: []types.BundleBody{
			{
				Tx: genUserTx(0, false),
			},
			{
				Tx: genUserTx(1, false),
			},
		},
	}

	backrun, backrunValue := genBackrunTx(0)
	bundle := &types.SBundle{
		Inclusion: types.BundleInclusion{
			BlockNumber:    testSuite.Header.Number.Uint64(),
			MaxBlockNumber: testSuite.Header.Number.Uint64(),
		},
		Body: []types.BundleBody{
			{
				Bundle: userBundle,
			},
			{
				Tx: backrun,
			},
		},
		Validity: types.BundleValidity{
			Refund: []types.RefundConstraint{
				{BodyIdx: 0, Percent: 90},
			},
		},
	}
	expectedRefunds := []TestCaseExtractedRefunds{
		{
			Value:   (*hexutil.U256)(backrunValue),
			Percent: 90,
			RefundSplit: map[common.Address]int{
				userAddress: 100,
			},
		},
	}
	pushSBundleTestCase("bundle with backrun of bundle", bundle, false, expectedRefunds)
}

func pushBackrunOfBundleWithRefundConfig() {
	userBundle := &types.SBundle{
		Inclusion: types.BundleInclusion{
			BlockNumber:    testSuite.Header.Number.Uint64(),
			MaxBlockNumber: testSuite.Header.Number.Uint64(),
		},
		Body: []types.BundleBody{
			{
				Tx: genUserTx(0, false),
			},
			{
				Tx: genUserTx(1, false),
			},
		},
		Validity: types.BundleValidity{
			RefundConfig: []types.RefundConfig{
				{
					Address: userAddress,
					Percent: 50,
				},
				{
					Address: searcherAddress,
					Percent: 50,
				},
			},
		},
	}

	backrun, backrunValue := genBackrunTx(0)
	bundle := &types.SBundle{
		Inclusion: types.BundleInclusion{
			BlockNumber:    testSuite.Header.Number.Uint64(),
			MaxBlockNumber: testSuite.Header.Number.Uint64(),
		},
		Body: []types.BundleBody{
			{
				Bundle: userBundle,
			},
			{
				Tx: backrun,
			},
		},
		Validity: types.BundleValidity{
			Refund: []types.RefundConstraint{
				{BodyIdx: 0, Percent: 90},
			},
		},
	}
	expectedRefunds := []TestCaseExtractedRefunds{
		{
			Value:   (*hexutil.U256)(backrunValue),
			Percent: 90,
			RefundSplit: map[common.Address]int{
				userAddress:     50,
				searcherAddress: 50,
			},
		},
	}
	pushSBundleTestCase("bundle with backrun of bundle with refund config", bundle, false, expectedRefunds)
}

func pushDoubleBackrunOfBundleWithRefundConfig() {
	backrun1, backrun1Value := genBackrunTx(0)
	backrun1Bundle := &types.SBundle{
		Inclusion: types.BundleInclusion{
			BlockNumber:    testSuite.Header.Number.Uint64(),
			MaxBlockNumber: testSuite.Header.Number.Uint64(),
		},
		Body: []types.BundleBody{
			{
				Tx: genUserTx(0, false),
			},
			{
				Tx: backrun1,
			},
		},
		Validity: types.BundleValidity{
			Refund: []types.RefundConstraint{
				{BodyIdx: 0, Percent: 90},
			},
			RefundConfig: []types.RefundConfig{
				{
					Address: searcherAddress,
					Percent: 100,
				},
			},
		},
	}

	backrun2, backrun2Value := genBackrunTx(1)
	bundle := &types.SBundle{
		Inclusion: types.BundleInclusion{
			BlockNumber:    testSuite.Header.Number.Uint64(),
			MaxBlockNumber: testSuite.Header.Number.Uint64(),
		},
		Body: []types.BundleBody{
			{
				Bundle: backrun1Bundle,
			},
			{
				Tx: backrun2,
			},
		},
		Validity: types.BundleValidity{
			Refund: []types.RefundConstraint{
				{BodyIdx: 0, Percent: 80},
			},
		},
	}

	expectedRefunds := []TestCaseExtractedRefunds{
		{
			Value:   (*hexutil.U256)(backrun1Value),
			Percent: 90,
			RefundSplit: map[common.Address]int{
				userAddress: 100,
			},
		},
		{
			Value:   (*hexutil.U256)(backrun2Value),
			Percent: 80,
			RefundSplit: map[common.Address]int{
				searcherAddress: 100,
			},
		},
	}
	pushSBundleTestCase("bundle with backrun of backrun of user tx", bundle, false, expectedRefunds)
}

func TestSBundles(t *testing.T) {
	generateTests()

	for _, tt := range testSuite.Tests {
		t.Run(tt.Name, func(t *testing.T) {
			var (
				config          = params.TestChainConfig
				signer          = types.LatestSigner(config)
				statedb, chData = genTestSetupWithAlloc(config, testSuite.GenesisAlloc, GasLimit)
				env             = newEnvironment(chData, statedb, testSuite.Header.Coinbase, testSuite.Header.GasLimit, testSuite.Header.BaseFee)
				envDiff         = newEnvironmentDiff(env)

				expectedKickbackValues    = make([]*uint256.Int, 0, len(tt.ExtractedRefunds))
				expectedKickbackReceivers = make([]common.Address, 0, len(tt.ExtractedRefunds))
			)
			for _, refund := range tt.ExtractedRefunds {
				refundBeforeSplit := common.PercentOf((*uint256.Int)(refund.Value), refund.Percent)

				fees := new(uint256.Int).Mul(uint256.MustFromBig(testSuite.Header.BaseFee), core.SbundlePayoutMaxCost)
				fees.Mul(fees, uint256.NewInt(uint64(len(refund.RefundSplit))))
				for recipient, split := range refund.RefundSplit {
					value := new(uint256.Int).Sub(refundBeforeSplit, fees)
					value = common.PercentOf(value, split)
					expectedKickbackValues = append(expectedKickbackValues, value)
					expectedKickbackReceivers = append(expectedKickbackReceivers, recipient)
				}
			}

			bundle, err := ethapi.ParseSBundleArgs(&tt.Bundle)
			require.NoError(t, err)
			sim := types.SimSBundle{
				Bundle: &bundle,
				// with such small values this bundle will never be rejected based on insufficient profit
				MevGasPrice: uint256.NewInt(1),
				Profit:      uint256.NewInt(1),
			}
			err = envDiff.commitSBundle(&sim, chData, nil, builderPrivKey, defaultAlgorithmConfig)
			if tt.ShouldFail {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			envDiff.baseEnvironment = env
			envDiff.applyToBaseEnv()

			var kickbackTxs []*types.Transaction
			for _, tx := range env.txs {
				sender, err := types.Sender(signer, tx)
				require.NoError(t, err)
				if sender == builderAddress {
					kickbackTxs = append(kickbackTxs, tx)
				}
			}
			require.Len(t, kickbackTxs, len(expectedKickbackValues))
			expectedKickbackFound := make([]int, len(expectedKickbackValues))
			for _, tx := range kickbackTxs {
				to := tx.To()
				require.NotNil(t, to)
				value := uint256.MustFromBig(tx.Value())
				for i := range expectedKickbackReceivers {
					if expectedKickbackReceivers[i] == *to && expectedKickbackValues[i].Cmp(value) == 0 {
						expectedKickbackFound[i]++
						break
					}
				}
			}
			for _, found := range expectedKickbackFound {
				require.Equal(t, 1, found)
			}
		})
	}
}
