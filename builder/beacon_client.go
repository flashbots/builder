package builder

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/log"
)

type testBeaconClient struct {
	validator *ValidatorPrivateData
	slot      uint64
}

func (b *testBeaconClient) isValidator(pubkey PubkeyHex) bool {
	return true
}
func (b *testBeaconClient) getProposerForNextSlot(requestedSlot uint64) (PubkeyHex, error) {
	return PubkeyHex(hexutil.Encode(b.validator.Pk)), nil
}
func (b *testBeaconClient) onForkchoiceUpdate() (uint64, error) {
	return b.slot, nil
}

func (b *testBeaconClient) updateValidatorsMap() error {
	return nil
}

type BeaconClient struct {
	endpoint      string
	slotsInEpoch  uint64
	secondsInSlot uint64

	mu               sync.Mutex
	currentEpoch     uint64
	currentSlot      uint64
	nextSlotProposer PubkeyHex
	slotProposerMap  map[uint64]PubkeyHex
}

func NewBeaconClient(endpoint string, slotsInEpoch uint64, secondsInSlot uint64) *BeaconClient {
	return &BeaconClient{
		endpoint:        endpoint,
		slotsInEpoch:    slotsInEpoch,
		secondsInSlot:   secondsInSlot,
		slotProposerMap: make(map[uint64]PubkeyHex),
	}
}

func (b *BeaconClient) isValidator(pubkey PubkeyHex) bool {
	return true
}

func (b *BeaconClient) getProposerForNextSlot(requestedSlot uint64) (PubkeyHex, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	nextSlotProposer, found := b.slotProposerMap[requestedSlot]
	if !found {
		log.Error("inconsistent proposer mapping", "requestSlot", requestedSlot, "slotProposerMap", b.slotProposerMap)
		return PubkeyHex(""), errors.New("inconsistent proposer mapping")
	}
	return nextSlotProposer, nil
}

func (b *BeaconClient) updateValidatorsMap() error {
	// Start regular slot updates
	slotsPerEpoch := b.slotsInEpoch
	durationPerSlot := time.Duration(b.secondsInSlot) * time.Second
	durationPerEpoch := durationPerSlot * time.Duration(slotsPerEpoch)
	// Every half epoch request validators map
	timer := time.NewTicker(durationPerEpoch / 2)
	defer timer.Stop()
	for ; true; <-timer.C {
		currentSlot, err := fetchCurrentSlot(b.endpoint)
		if err != nil {
			log.Error("could not get current slot", "err", err)
			continue
		}

		currentEpoch := currentSlot / b.slotsInEpoch
		if len(b.slotProposerMap) == 0 {
			slotProposerMap, err := fetchEpochProposersMap(b.endpoint, currentEpoch)
			if err != nil {
				log.Error("could not fetch validators map", "epoch", currentEpoch, "err", err)
				continue
			}

			b.mu.Lock()
			b.slotProposerMap = slotProposerMap
			b.mu.Unlock()
		}

		if currentEpoch > b.currentEpoch {
			slotProposerMap, err := fetchEpochProposersMap(b.endpoint, currentEpoch+1)
			if err != nil {
				log.Error("could not fetch validators map", "epoch", currentEpoch+1, "err", err)
				continue
			}

			prevEpoch := currentEpoch - 1
			b.mu.Lock()
			b.currentEpoch = currentEpoch
			// remove previous epoch slots
			for k := range b.slotProposerMap {
				if k/b.slotsInEpoch == prevEpoch {
					delete(b.slotProposerMap, k)
				}
			}
			// update the slot proposer map for next epoch
			for k, v := range slotProposerMap {
				b.slotProposerMap[k] = v
			}
			b.mu.Unlock()
		}

		timer.Reset(durationPerEpoch / 2)
	}
	return nil
}

/* Returns next slot's proposer pubkey */
// TODO: what happens if no block for previous slot - should still get next slot
func (b *BeaconClient) onForkchoiceUpdate() (uint64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	currentSlot, err := fetchCurrentSlot(b.endpoint)
	if err != nil {
		return 0, err
	}

	nextSlot := currentSlot + 1

	b.currentSlot = currentSlot
	nextSlotEpoch := nextSlot / b.slotsInEpoch

	if nextSlotEpoch != b.currentEpoch {
		// TODO: this should be prepared in advance, possibly just fetch for next epoch in advance
		slotProposerMap, err := fetchEpochProposersMap(b.endpoint, nextSlotEpoch)
		if err != nil {
			return 0, err
		}

		b.currentEpoch = nextSlotEpoch
		b.slotProposerMap = slotProposerMap
	}

	nextSlotProposer, found := b.slotProposerMap[nextSlot]
	if !found {
		log.Error("inconsistent proposer mapping", "currentSlot", currentSlot, "slotProposerMap", b.slotProposerMap)
		return 0, errors.New("inconsistent proposer mapping")
	}
	b.nextSlotProposer = nextSlotProposer
	return nextSlot, nil
}

func fetchCurrentSlot(endpoint string) (uint64, error) {
	headerRes := &struct {
		Data []struct {
			Root      common.Hash `json:"root"`
			Canonical bool        `json:"canonical"`
			Header    struct {
				Message struct {
					Slot          string      `json:"slot"`
					ProposerIndex string      `json:"proposer_index"`
					ParentRoot    common.Hash `json:"parent_root"`
					StateRoot     common.Hash `json:"state_root"`
					BodyRoot      common.Hash `json:"body_root"`
				} `json:"message"`
				Signature hexutil.Bytes `json:"signature"`
			} `json:"header"`
		} `json:"data"`
	}{}

	err := fetchBeacon(endpoint+"/eth/v1/beacon/headers", headerRes)
	if err != nil {
		return uint64(0), err
	}

	if len(headerRes.Data) != 1 {
		return uint64(0), errors.New("invalid response")
	}

	slot, err := strconv.Atoi(headerRes.Data[0].Header.Message.Slot)
	if err != nil {
		log.Error("could not parse slot", "Slot", headerRes.Data[0].Header.Message.Slot, "err", err)
		return uint64(0), errors.New("invalid response")
	}
	return uint64(slot), nil
}

func fetchEpochProposersMap(endpoint string, epoch uint64) (map[uint64]PubkeyHex, error) {
	proposerDutiesResponse := &struct {
		Data []struct {
			PubkeyHex string `json:"pubkey"`
			Slot      string `json:"slot"`
		} `json:"data"`
	}{}

	err := fetchBeacon(fmt.Sprintf("%s/eth/v1/validator/duties/proposer/%d", endpoint, epoch), proposerDutiesResponse)
	if err != nil {
		return nil, err
	}

	proposersMap := make(map[uint64]PubkeyHex)
	for _, proposerDuty := range proposerDutiesResponse.Data {
		slot, err := strconv.Atoi(proposerDuty.Slot)
		if err != nil {
			log.Error("could not parse slot", "Slot", proposerDuty.Slot, "err", err)
			continue
		}
		proposersMap[uint64(slot)] = PubkeyHex(proposerDuty.PubkeyHex)
	}
	return proposersMap, nil
}

func fetchBeacon(url string, dst any) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Error("invalid request", "url", url, "err", err)
		return err
	}
	req.Header.Set("accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Error("client refused", "url", url, "err", err)
		return err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error("could not read response body", "url", url, "err", err)
		return err
	}

	if resp.StatusCode >= 300 {
		ec := &struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}{}
		if err = json.Unmarshal(bodyBytes, ec); err != nil {
			log.Error("Couldn't unmarshal error from beacon node", "url", url, "body", string(bodyBytes))
			return errors.New("could not unmarshal error response from beacon node")
		}
		return errors.New(ec.Message)
	}

	err = json.Unmarshal(bodyBytes, dst)
	if err != nil {
		log.Error("could not unmarshal response", "url", url, "resp", string(bodyBytes), "dst", dst, "err", err)
		return err
	}

	log.Info("fetched", "url", url, "res", dst)
	return nil
}
