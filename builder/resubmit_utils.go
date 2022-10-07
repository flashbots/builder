package builder

import (
	"context"
	"time"

	"github.com/ethereum/go-ethereum/log"
	"golang.org/x/time/rate"
)

// runResubmitLoop checks for update signal and calls submit respecting provided rate limiter and context
func runResubmitLoop(ctx context.Context, limiter *rate.Limiter, updateSignal chan struct{}, submit func()) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-updateSignal:
			res := limiter.Reserve()
			if !res.OK() {
				log.Warn("resubmit loop failed to make limiter reservation")
				return
			}

			// check if we could make submission before context ctxDeadline
			if ctxDeadline, ok := ctx.Deadline(); ok {
				delayDeadline := time.Now().Add(res.Delay())
				if delayDeadline.After(ctxDeadline) {
					res.Cancel()
					return
				}
			}

			delay := res.Delay()
			if delay == 0 {
				submit()
				continue
			}

			t := time.NewTimer(delay)
			select {
			case <-t.C:
				submit()
				continue
			case <-ctx.Done():
				res.Cancel()
				t.Stop()
				return
			}
		}
	}
}

// runRetryLoop calls retry periodically with the provided interval respecting context cancellation
func runRetryLoop(ctx context.Context, interval time.Duration, retry func()) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			retry()
		}
	}
}
