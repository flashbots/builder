package builder

import (
	"context"
	"sync"
	"time"
)

type Resubmitter struct {
	mu     sync.Mutex
	cancel context.CancelFunc
}

func (r *Resubmitter) newTask(repeatFor time.Duration, interval time.Duration, fn func() error) error {
	repeatUntilCh := time.After(repeatFor)

	r.mu.Lock()
	if r.cancel != nil {
		r.cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.mu.Unlock()

	firstRunErr := fn()

	go func() {
		for ctx.Err() == nil {
			select {
			case <-ctx.Done():
				return
			case <-repeatUntilCh:
				cancel()
				return
			case <-time.After(interval):
				fn()
			}
		}
	}()

	return firstRunErr
}
