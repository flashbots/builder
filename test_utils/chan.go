package test_utils

import "time"

type ChanResult[V any] struct {
	Value   V
	Timeout bool
}

func RequireChan[V any](ch chan V, timeout time.Duration) ChanResult[V] {
	var v V
	select {
	case v = <-ch:
		return ChanResult[V]{v, false}
	case <-time.After(timeout):
		return ChanResult[V]{v, true}
	}

	return ChanResult[V]{v, true}
}
