package flashbotsextra

import (
	"math/big"
	"time"

	apiv1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/flashbots/go-utils/jsonrpc"
)

type RpcBlockClient struct {
	URL string
}

func NewRpcBlockClient(URL string) *RpcBlockClient {
	return &RpcBlockClient{URL: URL}
}

func (r *RpcBlockClient) ConsumeBuiltBlock(block *types.Block, blockValue *big.Int, ordersClosedAt time.Time, sealedAt time.Time, commitedBundles []types.SimulatedBundle, allBundles []types.SimulatedBundle, usedSbundles []types.UsedSBundle, bidTrace *apiv1.BidTrace) error {
	reqrpc := jsonrpc.JSONRPCRequest{
		ID:      nil,
		Method:  "block_consumeBuiltBlock",
		Version: "2.0",
		Params:  []interface{}{block.Header(), blockValue, ordersClosedAt, sealedAt, commitedBundles, allBundles, usedSbundles, bidTrace},
	}

	resp, err := jsonrpc.SendJSONRPCRequest(reqrpc, r.URL)
	if err != nil {
		return err
	}
	if resp.Error != nil {
		return resp.Error
	}
	return nil
}
