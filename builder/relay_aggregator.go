package builder

import (
	"errors"
	"fmt"
	"sync"

	"github.com/attestantio/go-builder-client/api/capella"
	"github.com/ethereum/go-ethereum/log"
	boostTypes "github.com/flashbots/go-boost-utils/types"
)

type RemoteRelayAggregator struct {
	relays []IRelay // in order of precedence, primary first

	registrationsCacheLock sync.RWMutex
	registrationsCacheSlot uint64
	registrationsCache     map[ValidatorData][]IRelay
}

func NewRemoteRelayAggregator(primary IRelay, secondary []IRelay) *RemoteRelayAggregator {
	relays := []IRelay{primary}
	return &RemoteRelayAggregator{
		relays: append(relays, secondary...),
	}
}

func (r *RemoteRelayAggregator) Start() error {
	for _, relay := range r.relays {
		err := relay.Start()
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *RemoteRelayAggregator) Stop() {
	for _, relay := range r.relays {
		relay.Stop()
	}
}

func (r *RemoteRelayAggregator) SubmitBlock(msg *boostTypes.BuilderSubmitBlockRequest, registration ValidatorData) error {
	r.registrationsCacheLock.RLock()
	defer r.registrationsCacheLock.RUnlock()

	relays, found := r.registrationsCache[registration]
	if !found {
		return fmt.Errorf("no relays for registration %s", registration.Pubkey)
	}
	for _, relay := range relays {
		go func(relay IRelay) {
			err := relay.SubmitBlock(msg, registration)
			if err != nil {
				log.Error("could not submit block", "err", err)
			}
		}(relay)
	}

	return nil
}

func (r *RemoteRelayAggregator) SubmitBlockCapella(msg *capella.SubmitBlockRequest, registration ValidatorData) error {
	r.registrationsCacheLock.RLock()
	defer r.registrationsCacheLock.RUnlock()

	relays, found := r.registrationsCache[registration]
	if !found {
		return fmt.Errorf("no relays for registration %s", registration.Pubkey)
	}
	for _, relay := range relays {
		go func(relay IRelay) {
			err := relay.SubmitBlockCapella(msg, registration)
			if err != nil {
				log.Error("could not submit block", "err", err)
			}
		}(relay)
	}

	return nil
}

type RelayValidatorRegistration struct {
	vd     ValidatorData
	relayI int // index into relays array to preserve relative order
}

func (r *RemoteRelayAggregator) GetValidatorForSlot(nextSlot uint64) (ValidatorData, error) {
	registrationsCh := make(chan *RelayValidatorRegistration, len(r.relays))
	for i, relay := range r.relays {
		go func(relay IRelay, relayI int) {
			vd, err := relay.GetValidatorForSlot(nextSlot)
			if err == nil {
				registrationsCh <- &RelayValidatorRegistration{vd: vd, relayI: relayI}
			} else if errors.Is(err, ErrValidatorNotFound) {
				registrationsCh <- nil
			} else {
				log.Error("could not get validator registration", "err", err)
				registrationsCh <- nil
			}
		}(relay, i)
	}

	topRegistrationCh := make(chan ValidatorData, 1)
	go r.updateRelayRegistrations(nextSlot, registrationsCh, topRegistrationCh)

	if vd, ok := <-topRegistrationCh; ok {
		return vd, nil
	}
	return ValidatorData{}, ErrValidatorNotFound
}

func (r *RemoteRelayAggregator) updateRelayRegistrations(nextSlot uint64, registrationsCh chan *RelayValidatorRegistration, topRegistrationCh chan ValidatorData) {
	defer close(topRegistrationCh)

	r.registrationsCacheLock.Lock()
	defer r.registrationsCacheLock.Unlock()

	if nextSlot < r.registrationsCacheSlot {
		// slot is outdated
		return
	}

	registrations := make([]*RelayValidatorRegistration, 0, len(r.relays))
	bestRelayIndex := len(r.relays)  // relay index of the topmost relay that gave us the registration
	bestRelayRegistrationIndex := -1 // index into the registrations for the registration returned by topmost relay
	for i := 0; i < len(r.relays); i++ {
		relayRegistration := <-registrationsCh
		if relayRegistration != nil {
			registrations = append(registrations, relayRegistration)
			// happy path for primary
			if relayRegistration.relayI == 0 {
				topRegistrationCh <- relayRegistration.vd
			}
			if relayRegistration.relayI < bestRelayIndex {
				bestRelayIndex = relayRegistration.relayI
				bestRelayRegistrationIndex = len(registrations) - 1
			}
		}
	}

	if len(registrations) == 0 {
		return
	}

	if bestRelayIndex != 0 {
		// if bestRelayIndex == 0 it was already sent
		topRegistrationCh <- registrations[bestRelayRegistrationIndex].vd
	}

	if nextSlot == r.registrationsCacheSlot {
		return
	}

	if nextSlot > r.registrationsCacheSlot {
		// clear the cache
		r.registrationsCache = make(map[ValidatorData][]IRelay)
		r.registrationsCacheSlot = nextSlot
	}

	for _, relayRegistration := range registrations {
		r.registrationsCache[relayRegistration.vd] = append(r.registrationsCache[relayRegistration.vd], r.relays[relayRegistration.relayI])
	}
}
