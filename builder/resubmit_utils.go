package builder

import (
	"context"
	"time"

	"github.com/ethereum/go-ethereum/log"
	"golang.org/x/time/rate"
)

// runResubmitLoop checks for update signal and calls submit respecting provided rate limiter and context
func runResubmitLoop(ctx context.Context, limiter *rate.Limiter, updateSignal <-chan struct{}, submit func(), submitTime time.Time) {
	if submitTime.IsZero() {
		log.Warn("skipping resubmit loop - zero submit time found")
		return
	}

	waitUntilSubmitTime := func(waitUntil time.Time) (ok bool, err error) {
		now := time.Now().UTC()
		if waitUntil.UTC().Before(now) {
			waitUntil = now
		}
		sleepTime := waitUntil.UTC().Sub(now.UTC())
		select {
		case <-ctx.Done():
			ok = false
		case <-time.After(sleepTime):
			ok = true
		}
		return ok && ctx.Err() == nil, ctx.Err()
	}

	if canContinue, err := waitUntilSubmitTime(submitTime); !canContinue {
		log.Warn("skipping resubmit loop - cannot continue", "error", err)
		return
	}

	var res *rate.Reservation
	for {
		select {
		case <-ctx.Done():
			return
		case <-updateSignal:
			// runBuildingJob is example caller that uses updateSignal channel via block hook that sends signal to
			// represent submissions that increase block profit

			res = limiter.Reserve()
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
