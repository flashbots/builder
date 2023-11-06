package flashbotsextra

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/require"
)

func simpleTx(nonce uint64) *types.Transaction {
	value := big.NewInt(1000000000000000) // in wei (0.001 eth)
	gasLimit := uint64(21000)             // in units
	gasPrice := big.NewInt(1000000000)

	toAddress := common.HexToAddress("0x7777492a736CD894Cb12DFE5e944047499AEF7a0")
	var data []byte
	return types.NewTx(&types.LegacyTx{
		Nonce:    nonce,
		To:       &toAddress,
		Value:    value,
		Gas:      gasLimit,
		GasPrice: gasPrice,
		Data:     data,
	})
}

func TestBundleUUIDHash(t *testing.T) {
	tx1 := simpleTx(1)
	tx2 := simpleTx(2)
	bts1, err := tx1.MarshalBinary()
	require.Nil(t, err)
	bts2, err := tx2.MarshalBinary()
	require.Nil(t, err)
	_, _ = bts1, bts2
	t.Run("no reverts", func(t *testing.T) {
		b := types.MevBundle{
			BlockNumber: big.NewInt(1),
			Hash:        common.HexToHash("0x135a7f22459b2102d51de2d6704512a03e1e2d2059c34bcbb659f4ba65e9f92c"),
		}

		require.Equal(t, "5171315f-6ba4-52b2-866e-e2390d422d81", b.ComputeUUID().String())
	})
	t.Run("one revert", func(t *testing.T) {
		b := types.MevBundle{
			BlockNumber: big.NewInt(1),
			Hash:        common.HexToHash("0x135a7f22459b2102d51de2d6704512a03e1e2d2059c34bcbb659f4ba65e9f92c"),
			RevertingTxHashes: []common.Hash{
				tx1.Hash(),
			},
		}

		require.Equal(t, "49dada39-6db2-500e-ae59-6cc18b2c19e0", b.ComputeUUID().String())
	})
}
