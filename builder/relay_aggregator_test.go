package builder

import (
	"errors"
	"testing"
	"time"

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
	submittedRegistration ValidatorData
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
func (r *testRelay) GetValidatorForSlot(nextSlot uint64) (ValidatorData, error) {
	r.requestedSlot = nextSlot
	return r.gvsVd, r.gvsErr
}

func TestRemoteRelayAggregator(t *testing.T) {
	testRelays := []*testRelay{&testRelay{}, &testRelay{}, &testRelay{}}
	ragg := NewRemoteRelayAggregator(testRelays[0], []IRelay{testRelays[1], testRelays[2]})

	// make all error out
	for _, r := range testRelays {
		r.gvsErr = errors.New("error!")
	}

	// Check getting validator slot - should error out if no relays return
	_, err := ragg.GetValidatorForSlot(10)
	require.Error(t, ErrValidatorNotFound, err)

	// If primary returns should not error out
	testRelays[0].gvsErr = nil
	_, err = ragg.GetValidatorForSlot(10)
	require.NoError(t, err)

	// If any returns should not error out
	testRelays[0].gvsErr = errors.New("error!")
	testRelays[2].gvsErr = nil
	_, err = ragg.GetValidatorForSlot(10)
	require.NoError(t, err)

	// Should return the more important relay if primary fails
	testRelays[1].gvsErr = nil
	testRelays[1].gvsVd.GasLimit = 20
	testRelays[2].gvsVd.GasLimit = 30
	vd, err := ragg.GetValidatorForSlot(10)
	require.NoError(t, err)
	require.Equal(t, uint64(20), vd.GasLimit)

	// Should return the primary if it returns
	testRelays[0].gvsErr = nil
	testRelays[0].gvsVd.GasLimit = 10
	vd, err = ragg.GetValidatorForSlot(11)
	require.NoError(t, err)
	require.Equal(t, uint64(10), vd.GasLimit)

	// let the validator registrations finish
	// TODO: notify from the test relays
	time.Sleep(10 * time.Millisecond)

	// if submitting for unseen VD should error out
	msg := &boostTypes.BuilderSubmitBlockRequest{}
	err = ragg.SubmitBlock(msg, ValidatorData{GasLimit: 40})
	require.Error(t, err)

	// should submit to the single pirmary if its the only one matching
	testRelays[0].submittedMsgCh = make(chan *boostTypes.BuilderSubmitBlockRequest, 1)
	err = ragg.SubmitBlock(msg, ValidatorData{GasLimit: 10})
	require.NoError(t, err)
	select {
	case rsMsg := <-testRelays[0].submittedMsgCh:
		require.Equal(t, msg, rsMsg)
	case <-time.After(time.Second):
		t.Fail()
	}

	// no other relay should have been asked
	require.Nil(t, testRelays[1].submittedMsg)
	require.Nil(t, testRelays[2].submittedMsg)
	testRelays[0].submittedMsgCh = nil

	testRelays[0].gvsVd.GasLimit = 30
	testRelays[1].gvsVd.GasLimit = 20
	testRelays[2].gvsVd.GasLimit = 30

	// should drop registrations if asked for the next slot
	vd, err = ragg.GetValidatorForSlot(12)
	require.NoError(t, err)
	require.Equal(t, uint64(30), vd.GasLimit)

	time.Sleep(10 * time.Millisecond)

	// should submit to multiple matching relays
	testRelays[0].submittedMsgCh = make(chan *boostTypes.BuilderSubmitBlockRequest, 1)
	testRelays[2].submittedMsgCh = make(chan *boostTypes.BuilderSubmitBlockRequest, 1)
	err = ragg.SubmitBlock(msg, ValidatorData{GasLimit: 10})
	require.Error(t, err)

	err = ragg.SubmitBlock(msg, ValidatorData{GasLimit: 30})
	require.NoError(t, err)

	select {
	case rsMsg := <-testRelays[0].submittedMsgCh:
		require.Equal(t, msg, rsMsg)
	case <-time.After(time.Second):
		t.Fail()
	}

	select {
	case rsMsg := <-testRelays[2].submittedMsgCh:
		require.Equal(t, msg, rsMsg)
	case <-time.After(time.Second):
		t.Fail()
	}
}
