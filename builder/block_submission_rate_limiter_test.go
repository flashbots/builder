package builder

import (
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/require"
)

func TestLimit(t *testing.T) {
	rl := NewBlockSubmissionRateLimiter()

	// Check that before starting requests are passed through
	ch1 := rl.Limit(&types.Block{Profit: new(big.Int)})
	ch2 := rl.Limit(&types.Block{Profit: new(big.Int)})
	ch3 := rl.Limit(&types.Block{Profit: new(big.Int)})

	time.Sleep(200 * time.Millisecond)

	for _, ch := range []chan bool{ch1, ch2, ch3} {
		select {
		case shouldSubmit := <-ch:
			require.True(t, shouldSubmit)
		default:
			t.Error("chan was not ready")
		}
	}

	// Check that after starting requests are rate limited
	rl.Start()

	// Check that before starting requests are passed through
	ch1 = rl.Limit(&types.Block{Profit: new(big.Int)})
	ch2 = rl.Limit(&types.Block{Profit: new(big.Int)})
	ch3 = rl.Limit(&types.Block{Profit: big.NewInt(1)})

	time.Sleep(200 * time.Millisecond)

	for _, ch := range []chan bool{ch1, ch2, ch3} {
		select {
		case shouldSubmit := <-ch:
			if ch == ch3 {
				require.True(t, shouldSubmit)
			} else {
				require.False(t, shouldSubmit)
			}
		default:
			t.Error("chan was not ready")
		}
	}

	// Check that after stopping requests are passed through
	rl.Stop()

	ch1 = rl.Limit(&types.Block{Profit: new(big.Int)})
	ch2 = rl.Limit(&types.Block{Profit: new(big.Int)})
	ch3 = rl.Limit(&types.Block{Profit: new(big.Int)})

	time.Sleep(200 * time.Millisecond)

	for _, ch := range []chan bool{ch1, ch2, ch3} {
		select {
		case shouldSubmit := <-ch:
			require.True(t, shouldSubmit)
		default:
			t.Error("chan was not ready")
		}
	}

}
