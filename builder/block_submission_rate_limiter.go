package builder

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
)

type blockRateLimitSubmission struct {
	resultCh chan bool
	block    *types.Block
}

type BlockSubmissionRateLimiter struct {
	submissionsCh chan blockRateLimitSubmission
	started       uint32
	ctx           context.Context
	cancel        context.CancelFunc
}

func NewBlockSubmissionRateLimiter() *BlockSubmissionRateLimiter {
	ctx, cancel := context.WithCancel(context.Background())
	r := &BlockSubmissionRateLimiter{
		submissionsCh: make(chan blockRateLimitSubmission),
		started:       uint32(0),
		ctx:           ctx,
		cancel:        cancel,
	}

	return r
}
func (r *BlockSubmissionRateLimiter) Limit(block *types.Block) chan bool {
	resultCh := make(chan bool, 1)
	if atomic.LoadUint32(&r.started) != 1 {
		resultCh <- true
		return resultCh
	}

	select {
	case r.submissionsCh <- blockRateLimitSubmission{
		resultCh: resultCh,
		block:    block,
	}:
	case <-r.ctx.Done():
		resultCh <- true
	}
	return resultCh
}

func (r *BlockSubmissionRateLimiter) Start() {
	if !atomic.CompareAndSwapUint32(&r.started, 0, 1) {
		return
	}

	go r.rateLimit()
}

func (r *BlockSubmissionRateLimiter) rateLimit() {
	for r.ctx.Err() == nil {
		// Beginning of the rate limit bucket
		bestSubmission := <-r.submissionsCh

		bucketCutoffCh := time.After(100 * time.Millisecond)

		bucketClosed := false
		for !bucketClosed {
			select {
			case <-r.ctx.Done():
				bucketClosed = true
				break
			case <-bucketCutoffCh:
				bucketClosed = true
				break
			case newSubmission := <-r.submissionsCh:
				if bestSubmission.block.Profit.Cmp(newSubmission.block.Profit) < 0 {
					bestSubmission.resultCh <- false
					bestSubmission = newSubmission
				} else {
					newSubmission.resultCh <- false
				}
			}
		}

		bestSubmission.resultCh <- true
	}
}

func (r *BlockSubmissionRateLimiter) Stop() {
	r.cancel()
}
