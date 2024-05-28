package validation

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"time"

	validation "github.com/ethereum/go-ethereum/eth/block-validation"
	"github.com/ethereum/go-ethereum/log"
	"github.com/gorilla/mux"
)

type BlockValidationApi struct {
	validationApi *validation.BlockValidationAPI
}

func (api *BlockValidationApi) getRouter() http.Handler {
	r := mux.NewRouter()

	r.HandleFunc("/", api.handleRoot).Methods(http.MethodGet)
	r.HandleFunc("/validate/block_submission", api.handleBuilderSubmission).Methods(http.MethodPost)
	return r
}

func (api *BlockValidationApi) handleRoot(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (api *BlockValidationApi) handleBuilderSubmission(w http.ResponseWriter, req *http.Request) {
	var prevTime, nextTime time.Time
	receivedAt := time.Now().UTC()
	prevTime = receivedAt

	var err error
	var r io.Reader = req.Body

	isGzip := req.Header.Get("Content-Encoding") == "gzip"
	if isGzip {
		r, err = gzip.NewReader(req.Body)
		if err != nil {
			log.Error("could not create gzip reader", "err", err)
			api.RespondError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	limitReader := io.LimitReader(r, 10*1024*1024) // 10 MB
	requestPayloadBytes, err := io.ReadAll(limitReader)
	if err != nil {
		log.Error("could not read payload", "err", err)
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	nextTime = time.Now().UTC()
	readTime := uint64(nextTime.Sub(prevTime).Microseconds())
	prevTime = nextTime

	payload := new(BuilderBlockValidationRequestV3)

	// Check for SSZ encoding
	contentType := req.Header.Get("Content-Type")
	if contentType == "application/octet-stream" {
		if err = payload.UnmarshalSSZ(requestPayloadBytes); err != nil {
			log.Error("could not decode payload - SSZ", "err", err)
		}
	} else {
		if err := json.Unmarshal(requestPayloadBytes, payload); err != nil {
			log.Error("could not decode payload - JSON", "err", err)
			api.RespondError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	nextTime = time.Now().UTC()
	decodeTime := uint64(nextTime.Sub(prevTime).Microseconds())
	prevTime = nextTime

	// Validate the payload
	err = api.validationApi.ValidateBuilderSubmissionV3(&validation.BuilderBlockValidationRequestV3{
		SubmitBlockRequest:    payload.SubmitBlockRequest,
		ParentBeaconBlockRoot: payload.ParentBeaconBlockRoot,
		RegisteredGasLimit:    payload.RegisteredGasLimit,
	})
	validationTime := uint64(time.Now().UTC().Sub(prevTime).Microseconds())

	l := log.New("isGzip", isGzip, "payloadBytes", len(requestPayloadBytes), "contentType", contentType,
		"numBlobs", len(payload.BlobsBundle.Blobs), "numTx", len(payload.ExecutionPayload.Transactions),
		"slot", payload.Message.Slot, "readTime", readTime, "decodeTime", decodeTime, "validationTime", validationTime)

	if err != nil {
		l.Info("Validation failed", "err", err)
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}
	l.Info("Validation successful")
	w.WriteHeader(http.StatusOK)
}

func (api *BlockValidationApi) RespondError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	// write the json response
	response := HTTPErrorResp{code, message}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Error("Couldn't write response", "error", err, "response", response)
		http.Error(w, "", http.StatusInternalServerError)
	}
}
