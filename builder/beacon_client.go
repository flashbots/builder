package builder

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/r3labs/sse"
	"golang.org/x/exp/slices"
)

type IBeaconClient interface {
	isValidator(pubkey PubkeyHex) bool
	getProposerForNextSlot(requestedSlot uint64) (PubkeyHex, error)
	SubscribeToPayloadAttributesEvents(payloadAttrC chan types.BuilderPayloadAttributes)
	Start() error
	Stop()
}

type testBeaconClient struct {
	validator *ValidatorPrivateData
	slot      uint64
}

func (b *testBeaconClient) Stop() {
	return
}

func (b *testBeaconClient) isValidator(pubkey PubkeyHex) bool {
	return true
}
func (b *testBeaconClient) getProposerForNextSlot(requestedSlot uint64) (PubkeyHex, error) {
	return PubkeyHex(hexutil.Encode(b.validator.Pk)), nil
}

func (b *testBeaconClient) SubscribeToPayloadAttributesEvents(payloadAttrC chan types.BuilderPayloadAttributes) {
}

func (b *testBeaconClient) Start() error { return nil }

type NilBeaconClient struct{}

func (b *NilBeaconClient) isValidator(pubkey PubkeyHex) bool {
	return false
}

func (b *NilBeaconClient) getProposerForNextSlot(requestedSlot uint64) (PubkeyHex, error) {
	return PubkeyHex(""), nil
}

func (b *NilBeaconClient) SubscribeToPayloadAttributesEvents(payloadAttrC chan types.BuilderPayloadAttributes) {
}

func (b *NilBeaconClient) Start() error { return nil }

func (b *NilBeaconClient) Stop() {}

type MultiBeaconClient struct {
	clients []*BeaconClient
	closeCh chan struct{}
}

func NewMultiBeaconClient(endpoints []string, slotsInEpoch uint64, secondsInSlot uint64) *MultiBeaconClient {
	clients := []*BeaconClient{}
	for _, endpoint := range endpoints {
		client := NewBeaconClient(endpoint, slotsInEpoch, secondsInSlot)
		clients = append(clients, client)
	}

	return &MultiBeaconClient{
		clients: clients,
		closeCh: make(chan struct{}),
	}
}

func (m *MultiBeaconClient) isValidator(pubkey PubkeyHex) bool {
	for _, c := range m.clients {
		// Pick the first one, always true
		return c.isValidator(pubkey)
	}

	return false
}

func (m *MultiBeaconClient) getProposerForNextSlot(requestedSlot uint64) (PubkeyHex, error) {
	var allErrs error
	for _, c := range m.clients {
		pk, err := c.getProposerForNextSlot(requestedSlot)
		if err != nil {
			allErrs = errors.Join(allErrs, err)
			continue
		}

		return pk, nil
	}
	return PubkeyHex(""), allErrs
}

func payloadAttributesMatch(l types.BuilderPayloadAttributes, r types.BuilderPayloadAttributes) bool {
	if l.Timestamp != r.Timestamp ||
		l.Random != r.Random ||
		l.SuggestedFeeRecipient != r.SuggestedFeeRecipient ||
		l.Slot != r.Slot ||
		l.HeadHash != r.HeadHash ||
		l.GasLimit != r.GasLimit {
		return false
	}

	if !slices.Equal(l.Withdrawals, r.Withdrawals) {
		return false
	}

	return true
}

func (m *MultiBeaconClient) SubscribeToPayloadAttributesEvents(payloadAttrC chan types.BuilderPayloadAttributes) {
	for _, c := range m.clients {
		go c.SubscribeToPayloadAttributesEvents(payloadAttrC)
	}
}

func (m *MultiBeaconClient) Start() error {
	var allErrs error
	for _, c := range m.clients {
		err := c.Start()
		if err != nil {
			allErrs = errors.Join(allErrs, err)
		}
	}
	return allErrs
}

func (m *MultiBeaconClient) Stop() {
	for _, c := range m.clients {
		c.Stop()
	}

	close(m.closeCh)
}

type BeaconClient struct {
	endpoint      string
	slotsInEpoch  uint64
	secondsInSlot uint64

	mu              sync.Mutex
	slotProposerMap map[uint64]PubkeyHex

	ctx      context.Context
	cancelFn context.CancelFunc
}

func NewBeaconClient(endpoint string, slotsInEpoch uint64, secondsInSlot uint64) *BeaconClient {
	ctx, cancelFn := context.WithCancel(context.Background())
	return &BeaconClient{
		endpoint:        endpoint,
		slotsInEpoch:    slotsInEpoch,
		secondsInSlot:   secondsInSlot,
		slotProposerMap: make(map[uint64]PubkeyHex),
		ctx:             ctx,
		cancelFn:        cancelFn,
	}
}

func (b *BeaconClient) Stop() {
	b.cancelFn()
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

func (b *BeaconClient) Start() error {
	go b.UpdateValidatorMapForever()
	return nil
}

func (b *BeaconClient) UpdateValidatorMapForever() {
	durationPerSlot := time.Duration(b.secondsInSlot) * time.Second

	prevFetchSlot := uint64(0)

	// fetch current epoch if beacon is online
	currentSlot, err := fetchCurrentSlot(b.endpoint)
	if err != nil {
		log.Error("could not get current slot", "err", err)
	} else {
		currentEpoch := currentSlot / b.slotsInEpoch
		slotProposerMap, err := fetchEpochProposersMap(b.endpoint, currentEpoch)
		if err != nil {
			log.Error("could not fetch validators map", "epoch", currentEpoch, "err", err)
		} else {
			b.mu.Lock()
			b.slotProposerMap = slotProposerMap
			b.mu.Unlock()
		}
	}

	retryDelay := time.Second

	// Every half epoch request validators map, polling for the slot
	// more frequently to avoid missing updates on errors
	timer := time.NewTimer(retryDelay)
	defer timer.Stop()
	for true {
		select {
		case <-b.ctx.Done():
			return
		case <-timer.C:
		}

		currentSlot, err := fetchCurrentSlot(b.endpoint)
		if err != nil {
			log.Error("could not get current slot", "err", err)
			timer.Reset(retryDelay)
			continue
		}

		// TODO: should poll after consistent slot within the epoch (slot % slotsInEpoch/2 == 0)
		nextFetchSlot := prevFetchSlot + b.slotsInEpoch/2
		if currentSlot < nextFetchSlot {
			timer.Reset(time.Duration(nextFetchSlot-currentSlot) * durationPerSlot)
			continue
		}

		currentEpoch := currentSlot / b.slotsInEpoch
		slotProposerMap, err := fetchEpochProposersMap(b.endpoint, currentEpoch+1)
		if err != nil {
			log.Error("could not fetch validators map", "epoch", currentEpoch+1, "err", err)
			timer.Reset(retryDelay)
			continue
		}

		prevFetchSlot = currentSlot
		b.mu.Lock()
		// remove previous epoch slots
		for k := range b.slotProposerMap {
			if k < currentEpoch*b.slotsInEpoch {
				delete(b.slotProposerMap, k)
			}
		}
		// update the slot proposer map for next epoch
		for k, v := range slotProposerMap {
			b.slotProposerMap[k] = v
		}
		b.mu.Unlock()

		timer.Reset(time.Duration(nextFetchSlot-currentSlot) * durationPerSlot)
	}
}

// PayloadAttributesEvent represents the data of a payload_attributes event
// {"version": "capella", "data": {"proposer_index": "123", "proposal_slot": "10", "parent_block_number": "9", "parent_block_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2", "parent_block_hash": "0x9a2fefd2fdb57f74993c7780ea5b9030d2897b615b89f808011ca5aebed54eaf", "payload_attributes": {"timestamp": "123456", "prev_randao": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2", "suggested_fee_recipient": "0x0000000000000000000000000000000000000000", "withdrawals": [{"index": "5", "validator_index": "10", "address": "0x0000000000000000000000000000000000000000", "amount": "15640"}]}}}
type PayloadAttributesEvent struct {
	Version string                     `json:"version"`
	Data    PayloadAttributesEventData `json:"data"`
}

type PayloadAttributesEventData struct {
	ProposalSlot      uint64            `json:"proposal_slot,string"`
	ParentBlockHash   common.Hash       `json:"parent_block_hash"`
	PayloadAttributes PayloadAttributes `json:"payload_attributes"`
}

type PayloadAttributes struct {
	Timestamp             uint64                `json:"timestamp,string"`
	PrevRandao            common.Hash           `json:"prev_randao"`
	SuggestedFeeRecipient common.Address        `json:"suggested_fee_recipient"`
	Withdrawals           []*capella.Withdrawal `json:"withdrawals"`
}

// SubscribeToPayloadAttributesEvents subscribes to payload attributes events to validate fields such as prevrandao and withdrawals
func (b *BeaconClient) SubscribeToPayloadAttributesEvents(payloadAttrC chan types.BuilderPayloadAttributes) {
	payloadAttributesResp := new(PayloadAttributesEvent)

	eventsURL := fmt.Sprintf("%s/eth/v1/events?topics=payload_attributes", b.endpoint)
	log.Info("subscribing to payload_attributes events")

	for {
		client := sse.NewClient(eventsURL)
		err := client.SubscribeRawWithContext(b.ctx, func(msg *sse.Event) {
			err := json.Unmarshal(msg.Data, payloadAttributesResp)
			if err != nil {
				log.Error("could not unmarshal payload_attributes event", "err", err)
			} else {
				// convert capella.Withdrawal to types.Withdrawal
				var withdrawals []*types.Withdrawal
				for _, w := range payloadAttributesResp.Data.PayloadAttributes.Withdrawals {
					withdrawals = append(withdrawals, &types.Withdrawal{
						Index:     uint64(w.Index),
						Validator: uint64(w.ValidatorIndex),
						Address:   common.Address(w.Address),
						Amount:    uint64(w.Amount),
					})
				}

				data := types.BuilderPayloadAttributes{
					Slot:                  payloadAttributesResp.Data.ProposalSlot,
					HeadHash:              payloadAttributesResp.Data.ParentBlockHash,
					Timestamp:             hexutil.Uint64(payloadAttributesResp.Data.PayloadAttributes.Timestamp),
					Random:                payloadAttributesResp.Data.PayloadAttributes.PrevRandao,
					SuggestedFeeRecipient: payloadAttributesResp.Data.PayloadAttributes.SuggestedFeeRecipient,
					Withdrawals:           withdrawals,
				}
				payloadAttrC <- data
			}
		})
		if err != nil {
			log.Error("failed to subscribe to payload_attributes events", "err", err)
			time.Sleep(1 * time.Second)
		}
		log.Warn("beaconclient SubscribeRaw ended, reconnecting")
	}
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
