package builder

import (
	"context"
	"time"

	"github.com/ethereum/go-ethereum/log"
	"golang.org/x/time/rate"
)

// runResubmitLoop checks for update signal and calls submit respecting provided rate limiter and context
func runResubmitLoop(ctx context.Context, limiter *rate.Limiter, updateSignal chan struct{}, submit func(), submitTime *time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-updateSignal:
			var res *rate.Reservation
			if submitTime == nil {
				res = limiter.Reserve()
			} else {
				now := time.Now()
				sleepTime := submitTime.UTC().UnixMilli() - now.UTC().UnixMilli()
				log.Debug("resubmit loop",
					"now-sec", now.UTC().Unix(),
					"slot", ctx.Value(key("slot")),
					"slot-sec", submitTime.Add(4*time.Second).Unix(),
					"delta-now-from-slot-ms", submitTime.Add(4*time.Second).Sub(now).Milliseconds(),
					"block-time-sec", ctx.Value(key("timestamp")))
				time.Sleep(time.Duration(sleepTime) * time.Millisecond)
				res = limiter.Reserve()
			}

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
