package builder

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestResubmitter(t *testing.T) {

	resubmitter := Resubmitter{}

	pingCh := make(chan error)
	go func() {
		res := resubmitter.newTask(time.Second, 100*time.Millisecond, func() error {
			return <-pingCh
		})
		require.ErrorContains(t, res, "xx")
	}()

	select {
	case pingCh <- errors.New("xx"):
	case <-time.After(time.Second):
		t.Error("timeout waiting for the function")
	}

	select {
	case pingCh <- nil:
		t.Error("function restarted too soon")
	default:
	}

	time.Sleep(200 * time.Millisecond)

	select {
	case pingCh <- nil:
	default:
		t.Error("function restarted too late")
	}

	time.Sleep(800 * time.Millisecond)

	select {
	case pingCh <- nil:
	default:
		t.Error("function restarted too late")
	}

	select {
	case pingCh <- nil:
		t.Error("function restarted after deadline")
	case <-time.After(200 * time.Millisecond):
	}
}
