package builder

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/attestantio/go-builder-client/api/capella"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/log"
	boostTypes "github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/mev-boost/server"
	"github.com/gorilla/websocket"
)

var ErrValidatorNotFound = errors.New("validator not found")

type RemoteRelay struct {
	endpoint string
	client   http.Client

	localRelay *LocalRelay

	validatorsLock       sync.RWMutex
	validatorSyncOngoing bool
	lastRequestedSlot    uint64
	validatorSlotMap     map[uint64]ValidatorData

	bidSubmissionChan chan *[]byte
	websocketEnabled  bool
}

func NewRemoteRelay(endpoint string, localRelay *LocalRelay, enableWS bool) *RemoteRelay {
	r := &RemoteRelay{
		endpoint:             endpoint,
		client:               http.Client{Timeout: time.Second},
		localRelay:           localRelay,
		validatorSyncOngoing: false,
		lastRequestedSlot:    0,
		validatorSlotMap:     make(map[uint64]ValidatorData),

		bidSubmissionChan: make(chan *[]byte),
		websocketEnabled:  enableWS,
	}

	if r.websocketEnabled {
		conn, err := r.ConnectToWebsocket()
		if err != nil {
			log.Error("could not connect to websocket")
			return nil
		}
		go r.maintainConnection(conn)
		return r
	}

	err := r.updateValidatorsMap(0, 3)
	if err != nil {
		log.Error("could not connect to remote relay, continuing anyway", "err", err)
	}

	return r
}

type GetValidatorRelayResponse []struct {
	Slot  uint64 `json:"slot,string"`
	Entry struct {
		Message struct {
			FeeRecipient string `json:"fee_recipient"`
			GasLimit     uint64 `json:"gas_limit,string"`
			Timestamp    uint64 `json:"timestamp,string"`
			Pubkey       string `json:"pubkey"`
		} `json:"message"`
		Signature string `json:"signature"`
	} `json:"entry"`
}

func (r *RemoteRelay) updateValidatorsMap(currentSlot uint64, retries int) error {
	r.validatorsLock.Lock()
	if r.validatorSyncOngoing {
		r.validatorsLock.Unlock()
		return errors.New("sync is ongoing")
	}
	r.validatorSyncOngoing = true
	r.validatorsLock.Unlock()

	log.Info("requesting ", "currentSlot", currentSlot)
	newMap, err := r.getSlotValidatorMapFromRelay()
	for err != nil && retries > 0 {
		log.Error("could not get validators map from relay, retrying", "err", err)
		time.Sleep(time.Second)
		newMap, err = r.getSlotValidatorMapFromRelay()
		retries -= 1
	}
	r.validatorsLock.Lock()
	r.validatorSyncOngoing = false
	if err != nil {
		r.validatorsLock.Unlock()
		log.Error("could not get validators map from relay", "err", err)
		return err
	}

	r.validatorSlotMap = newMap
	r.lastRequestedSlot = currentSlot
	r.validatorsLock.Unlock()

	log.Info("Updated validators", "count", len(newMap), "slot", currentSlot)
	return nil
}

func (r *RemoteRelay) GetValidatorForSlot(nextSlot uint64) (ValidatorData, error) {
	// next slot is expected to be the actual chain's next slot, not something requested by the user!
	// if not sanitized it will force resync of validator data and possibly is a DoS vector

	r.validatorsLock.RLock()
	if r.lastRequestedSlot == 0 || nextSlot/32 > r.lastRequestedSlot/32 {
		// Every epoch request validators map
		go func() {
			err := r.updateValidatorsMap(nextSlot, 1)
			if err != nil {
				log.Error("could not update validators map", "err", err)
			}
		}()
	}

	vd, found := r.validatorSlotMap[nextSlot]
	r.validatorsLock.RUnlock()

	if r.localRelay != nil {
		localValidator, err := r.localRelay.GetValidatorForSlot(nextSlot)
		if err == nil {
			log.Info("Validator registration overwritten by local data", "slot", nextSlot, "validator", localValidator)
			return localValidator, nil
		}
	}

	if found {
		return vd, nil
	}

	return ValidatorData{}, ErrValidatorNotFound
}

func (r *RemoteRelay) Start() error {
	return nil
}

func (r *RemoteRelay) Stop() {}

func (r *RemoteRelay) SubmitBlock(msg *boostTypes.BuilderSubmitBlockRequest, _ ValidatorData) error {
	log.Info("submitting block to remote relay", "endpoint", r.endpoint)
	code, err := server.SendHTTPRequest(context.TODO(), *http.DefaultClient, http.MethodPost, r.endpoint+"/relay/v1/builder/blocks", msg, nil)
	if err != nil {
		return fmt.Errorf("error sending http request to relay %s. err: %w", r.endpoint, err)
	}
	if code > 299 {
		return fmt.Errorf("non-ok response code %d from relay %s", code, r.endpoint)
	}

	if r.localRelay != nil {
		r.localRelay.submitBlock(msg)
	}

	return nil
}

func (r *RemoteRelay) SubmitBlockCapella(msg *capella.SubmitBlockRequest, _ ValidatorData) error {

	if r.websocketEnabled {
		payloadBytes, err := json.Marshal(msg)
		if err != nil {
			return err
		}
		r.bidSubmissionChan <- &payloadBytes
		return nil
	}

	log.Info("submitting block to remote relay", "endpoint", r.endpoint)
	code, err := server.SendHTTPRequest(context.TODO(), *http.DefaultClient, http.MethodPost, r.endpoint+"/relay/v1/builder/blocks", msg, nil)
	if err != nil {
		return fmt.Errorf("error sending http request to relay %s. err: %w", r.endpoint, err)
	}
	if code > 299 {
		return fmt.Errorf("non-ok response code %d from relay %s", code, r.endpoint)
	}

	if r.localRelay != nil {
		r.localRelay.submitBlockCapella(msg)
	}

	return nil
}

func (r *RemoteRelay) getSlotValidatorMapFromRelay() (map[uint64]ValidatorData, error) {
	var dst GetValidatorRelayResponse
	code, err := server.SendHTTPRequest(context.TODO(), *http.DefaultClient, http.MethodGet, r.endpoint+"/relay/v1/builder/validators", nil, &dst)
	if err != nil {
		return nil, err
	}

	if code > 299 {
		return nil, fmt.Errorf("non-ok response code %d from relay", code)
	}

	res := make(map[uint64]ValidatorData)
	for _, data := range dst {
		feeRecipientBytes, err := hexutil.Decode(data.Entry.Message.FeeRecipient)
		if err != nil {
			log.Error("Ill-formatted fee_recipient from relay", "data", data)
			continue
		}
		var feeRecipient boostTypes.Address
		feeRecipient.FromSlice(feeRecipientBytes[:])

		pubkeyHex := PubkeyHex(strings.ToLower(data.Entry.Message.Pubkey))

		res[data.Slot] = ValidatorData{
			Pubkey:       pubkeyHex,
			FeeRecipient: feeRecipient,
			GasLimit:     data.Entry.Message.GasLimit,
		}
	}

	return res, nil
}

func (r *RemoteRelay) ConnectToWebsocket() (*websocket.Conn, error) {

	wsURL := fmt.Sprintf("%s/blxr/ws", r.endpoint)
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil) // requires blxr's http auth header
	if err != nil {
		log.Info("Could not connect to relay websocket", "url", wsURL, "err", err)
		return conn, err
	}

	return conn, nil
}

func (r *RemoteRelay) maintainConnection(conn *websocket.Conn) {

	// if the connection closes optionally just reconnect and maintain

	// defer func() {
	// 	time.Sleep(15 * time.Second)
	// 	conn, err := r.ConnectToWebsocket()
	// 	if err != nil {
	// 		log.Error("could not connect to webocket")
	// 		return
	// 	}
	// 	go r.maintainConnection(conn)
	// }()

	conn.SetCloseHandler(func(code int, text string) error {
		log.Warn("connection closed with code and message", "code", code, "message", text)
		return nil
	})

	ticker := time.NewTicker(15 * time.Second)

	for {
		select {
		case <-ticker.C:

			// send ping
			if err := conn.WriteMessage(websocket.PingMessage, []byte("ping")); err != nil {
				log.Error("failed to ping websocket", "error", err.Error())
				return
			}

			// read message
			_, res, err := conn.ReadMessage()
			if err != nil {
				log.Error("failed to read message from websocket", "error", err.Error())
				return
			}

			log.Info("message received from websocket", "message", string(res))

		case bid := <-r.bidSubmissionChan:

			// reset ticker, no need to ping if we're already writing a message
			ticker.Reset(15 * time.Second)

			// send bid
			if err := conn.WriteMessage(websocket.TextMessage, *bid); err != nil {
				log.Error("failed write bid to socket", "error", err.Error())
				return
			}

			// read message
			_, res, err := conn.ReadMessage()
			if err != nil {
				log.Error("failed to read message from websocket", "error", err.Error())
				return
			}

			log.Info("message received from websocket", "message", string(res))
		}

	}
}
