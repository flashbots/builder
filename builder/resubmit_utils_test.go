package builder

import (
	"context"
	"math/rand"
	"sort"
	"sync"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

type submission struct {
	t time.Time
	v int
}

func TestResubmitUtils(t *testing.T) {
	const (
		totalTime        = time.Second
		rateLimitTime    = 100 * time.Millisecond
		resubmitInterval = 10 * time.Millisecond
	)

	ctx, cancel := context.WithTimeout(context.Background(), totalTime)
	defer cancel()
	limiter := rate.NewLimiter(rate.Every(rateLimitTime), 1)

	var (
		signal  = make(chan struct{}, 1)
		subMu   sync.Mutex
		subLast int
		subBest int
		subAll  []submission
	)

	go runResubmitLoop(ctx, limiter, signal, func() {
		subMu.Lock()
		defer subMu.Unlock()

		if subBest > subLast {
			subAll = append(subAll, submission{time.Now(), subBest})
			subLast = subBest
		}
	})

	runRetryLoop(ctx, resubmitInterval, func() {
		subMu.Lock()
		defer subMu.Unlock()

		value := rand.Int()
		if value > subBest {
			subBest = value

			select {
			case signal <- struct{}{}:
			default:
			}
		}
	})

	sorted := sort.SliceIsSorted(subAll, func(i, j int) bool {
		return subAll[i].v < subAll[j].v
	})
	if !sorted {
		t.Error("submissions are not sorted")
	}

	for i := 0; i < len(subAll)-1; i++ {
		interval := subAll[i+1].t.Sub(subAll[i].t)
		if interval+10*time.Millisecond < rateLimitTime {
			t.Errorf("submissions are not rate limited: interval %s, limit %s", interval, rateLimitTime)
		}
	}
}
