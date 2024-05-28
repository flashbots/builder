package validation

import (
	"encoding/json"

	builderApiDeneb "github.com/attestantio/go-builder-client/api/deneb"
	builderApiV1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/ethereum/go-ethereum/common"
)

type HTTPErrorResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type BuilderBlockValidationRequestV3 struct {
	builderApiDeneb.SubmitBlockRequest
	ParentBeaconBlockRoot common.Hash `json:"parent_beacon_block_root" ssz-size:"32"`
	RegisteredGasLimit    uint64      `json:"registered_gas_limit,string"`
}

func (r *BuilderBlockValidationRequestV3) MarshalJSON() ([]byte, error) {
	type denebBuilderBlockValidationRequestJSON struct {
		Message               *builderApiV1.BidTrace       `json:"message"`
		ExecutionPayload      *deneb.ExecutionPayload      `json:"execution_payload"`
		BlobsBundle           *builderApiDeneb.BlobsBundle `json:"blobs_bundle"`
		Signature             string                       `json:"signature"`
		RegisteredGasLimit    uint64                       `json:"registered_gas_limit,string"`
		ParentBeaconBlockRoot string                       `json:"parent_beacon_block_root"`
	}

	return json.Marshal(&denebBuilderBlockValidationRequestJSON{
		Message:               r.Message,
		ExecutionPayload:      r.ExecutionPayload,
		BlobsBundle:           r.BlobsBundle,
		Signature:             r.Signature.String(),
		RegisteredGasLimit:    r.RegisteredGasLimit,
		ParentBeaconBlockRoot: r.ParentBeaconBlockRoot.String(),
	})
}

func (r *BuilderBlockValidationRequestV3) UnmarshalJSON(data []byte) error {
	params := &struct {
		ParentBeaconBlockRoot common.Hash `json:"parent_beacon_block_root"`
		RegisteredGasLimit    uint64      `json:"registered_gas_limit,string"`
	}{}
	err := json.Unmarshal(data, params)
	if err != nil {
		return err
	}
	r.RegisteredGasLimit = params.RegisteredGasLimit
	r.ParentBeaconBlockRoot = params.ParentBeaconBlockRoot

	blockRequest := new(builderApiDeneb.SubmitBlockRequest)
	err = json.Unmarshal(data, &blockRequest)
	if err != nil {
		return err
	}
	r.SubmitBlockRequest = *blockRequest
	return nil
}
