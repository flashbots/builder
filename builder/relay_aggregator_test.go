package builder

import (
	"errors"
	"testing"
	"time"

	"github.com/attestantio/go-builder-client/api/capella"
	boostTypes "github.com/flashbots/go-boost-utils/types"
	"github.com/stretchr/testify/require"
)

/*
	validator     ValidatorData
	requestedSlot uint64
	submittedMsg  *boostTypes.BuilderSubmitBlockRequest
*/

type testRelay struct {
	sbError error
	gvsVd   ValidatorData
	gvsErr  error

	requestedSlot         uint64
	submittedMsg          *boostTypes.BuilderSubmitBlockRequest
	submittedMsgCh        chan *boostTypes.BuilderSubmitBlockRequest
	submittedMsgCapella   *capella.SubmitBlockRequest
	submittedMsgChCapella chan *capella.SubmitBlockRequest
}

type testRelayAggBackend struct {
	relays []*testRelay
	ragg   *RemoteRelayAggregator
}

func newTestRelayAggBackend(numRelay int) *testRelayAggBackend {
	testRelays := make([]*testRelay, numRelay)
	secondaryRelays := make([]IRelay, numRelay-1)
	for i := 0; i < numRelay; i++ {
		testRelays[i] = &testRelay{}
		if i > 0 {
			secondaryRelays[i-1] = testRelays[i]
		}
	}
	ragg := NewRemoteRelayAggregator(testRelays[0], secondaryRelays)
	return &testRelayAggBackend{testRelays, ragg}
}

func (r *testRelay) SubmitBlock(msg *boostTypes.BuilderSubmitBlockRequest, registration ValidatorData) error {
	if r.submittedMsgCh != nil {
		select {
		case r.submittedMsgCh <- msg:
		default:
		}
	}
	r.submittedMsg = msg
	return r.sbError
}

func (r *testRelay) SubmitBlockCapella(msg *capella.SubmitBlockRequest, registration ValidatorData) error {
	if r.submittedMsgCh != nil {
		select {
		case r.submittedMsgChCapella <- msg:
		default:
		}
	}
	r.submittedMsgCapella = msg
	return r.sbError
}

func (r *testRelay) GetValidatorForSlot(nextSlot uint64) (ValidatorData, error) {
	r.requestedSlot = nextSlot
	return r.gvsVd, r.gvsErr
}

func (r *testRelay) Start() error {
	return nil
}

func (r *testRelay) Stop() {}

func TestRemoteRelayAggregator(t *testing.T) {
	t.Run("should return error if no relays return validator data", func(t *testing.T) {
		backend := newTestRelayAggBackend(3)
		// make all error out
		for _, r := range backend.relays {
			r.gvsErr = errors.New("error!")
		}

		// Check getting validator slot - should error out if no relays return
		_, err := backend.ragg.GetValidatorForSlot(10)
		require.Error(t, ErrValidatorNotFound, err)
	})

	t.Run("should return validator if one relay returns validator data", func(t *testing.T) {
		backend := newTestRelayAggBackend(3)

		// If primary returns should not error out
		backend.relays[1].gvsErr = errors.New("error!")
		backend.relays[2].gvsErr = errors.New("error!")
		_, err := backend.ragg.GetValidatorForSlot(10)
		require.NoError(t, err)

		// If any returns should not error out
		backend.relays[0].gvsErr = errors.New("error!")
		backend.relays[2].gvsErr = nil
		_, err = backend.ragg.GetValidatorForSlot(10)
		require.NoError(t, err)
	})

	t.Run("should return the more important (lower index) relay validator data", func(t *testing.T) {
		backend := newTestRelayAggBackend(3)

		// Should return the more important relay if primary fails
		backend.relays[0].gvsErr = errors.New("error!")
		backend.relays[1].gvsVd.GasLimit = 20
		backend.relays[2].gvsVd.GasLimit = 30
		vd, err := backend.ragg.GetValidatorForSlot(10)
		require.NoError(t, err)
		require.Equal(t, uint64(20), vd.GasLimit)

		// Should return the primary if it returns
		backend.relays[0].gvsErr = nil
		backend.relays[0].gvsVd.GasLimit = 10
		vd, err = backend.ragg.GetValidatorForSlot(11)
		require.NoError(t, err)
		require.Equal(t, uint64(10), vd.GasLimit)
	})

	t.Run("should error submitting to unseen validator data", func(t *testing.T) {
		backend := newTestRelayAggBackend(3)

		backend.relays[0].gvsVd.GasLimit = 10

		vd, err := backend.ragg.GetValidatorForSlot(10)
		require.NoError(t, err)
		require.Equal(t, uint64(10), vd.GasLimit)

		// let the validator registrations finish
		// TODO: notify from the test relays
		time.Sleep(10 * time.Millisecond)

		// if submitting for unseen VD should error out
		msg := &boostTypes.BuilderSubmitBlockRequest{}
		err = backend.ragg.SubmitBlock(msg, ValidatorData{GasLimit: 40})
		require.Error(t, err)
	})

	t.Run("should submit to relay with matching validator data", func(t *testing.T) {
		backend := newTestRelayAggBackend(3)

		backend.relays[0].gvsVd.GasLimit = 10
		backend.relays[1].gvsVd.GasLimit = 20
		backend.relays[2].gvsVd.GasLimit = 30

		vd, err := backend.ragg.GetValidatorForSlot(11)
		require.NoError(t, err)
		require.Equal(t, uint64(10), vd.GasLimit)

		// let the validator registrations finish
		// TODO: notify from the test relays
		time.Sleep(10 * time.Millisecond)

		// if submitting for unseen VD should error out
		msg := &boostTypes.BuilderSubmitBlockRequest{}
		err = backend.ragg.SubmitBlock(msg, ValidatorData{GasLimit: 40})
		require.Error(t, err)

		// should submit to the single pirmary if its the only one matching
		backend.relays[0].submittedMsgCh = make(chan *boostTypes.BuilderSubmitBlockRequest, 1)
		err = backend.ragg.SubmitBlock(msg, ValidatorData{GasLimit: 10})
		require.NoError(t, err)
		select {
		case rsMsg := <-backend.relays[0].submittedMsgCh:
			require.Equal(t, msg, rsMsg)
		case <-time.After(time.Second):
			t.Fail()
		}

		// no other relay should have been asked
		require.Nil(t, backend.relays[1].submittedMsg)
		require.Nil(t, backend.relays[2].submittedMsg)
	})

	t.Run("should submit to relays with matching validator data and drop registrations on next slot", func(t *testing.T) {
		backend := newTestRelayAggBackend(3)

		backend.relays[0].gvsVd.GasLimit = 10
		backend.relays[1].gvsVd.GasLimit = 20
		backend.relays[2].gvsVd.GasLimit = 30

		vd, err := backend.ragg.GetValidatorForSlot(11)
		require.NoError(t, err)
		require.Equal(t, uint64(10), vd.GasLimit)

		// let the validator registrations finish
		time.Sleep(10 * time.Millisecond)

		backend.relays[0].gvsVd.GasLimit = 30
		backend.relays[1].gvsVd.GasLimit = 20
		backend.relays[2].gvsVd.GasLimit = 30

		// should drop registrations if asked for the next slot
		vd, err = backend.ragg.GetValidatorForSlot(12)
		require.NoError(t, err)
		require.Equal(t, uint64(30), vd.GasLimit)

		time.Sleep(10 * time.Millisecond)

		// should submit to multiple matching relays
		backend.relays[0].submittedMsgCh = make(chan *boostTypes.BuilderSubmitBlockRequest, 1)
		backend.relays[2].submittedMsgCh = make(chan *boostTypes.BuilderSubmitBlockRequest, 1)
		msg := &boostTypes.BuilderSubmitBlockRequest{}
		err = backend.ragg.SubmitBlock(msg, ValidatorData{GasLimit: 10})
		require.Error(t, err)

		err = backend.ragg.SubmitBlock(msg, ValidatorData{GasLimit: 30})
		require.NoError(t, err)

		select {
		case rsMsg := <-backend.relays[0].submittedMsgCh:
			require.Equal(t, msg, rsMsg)
		case <-time.After(time.Second):
			t.Fail()
		}

		select {
		case rsMsg := <-backend.relays[2].submittedMsgCh:
			require.Equal(t, msg, rsMsg)
		case <-time.After(time.Second):
			t.Fail()
		}
	})
}
