package flashbotsextra

import (
	"math/big"
	"time"

	apiv1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/flashbots/go-utils/jsonrpc"
)

type RpcBlockClient struct {
	URL string
}

func NewRpcBlockClient(URL string) *RpcBlockClient {
	return &RpcBlockClient{URL: URL}
}

func (r *RpcBlockClient) ConsumeBuiltBlock(block *types.Block, blockValue *big.Int, ordersClosedAt time.Time, sealedAt time.Time,
	commitedBundles []types.SimulatedBundle, allBundles []types.SimulatedBundle,
	usedSbundles []types.UsedSBundle, bidTrace *apiv1.BidTrace,
) {
	reqrpc := jsonrpc.JSONRPCRequest{
		ID:      nil,
		Method:  "block_consumeBuiltBlock",
		Version: "2.0",
		Params:  []interface{}{block.Header(), blockValue, ordersClosedAt, sealedAt, commitedBundles, allBundles, usedSbundles, bidTrace},
	}

	resp, err := jsonrpc.SendJSONRPCRequest(reqrpc, r.URL)
	if err != nil {
		log.Error("could not send rpc request", "err", err)
	} else {
		log.Info("successfully relayed data to block processor via json rpc", "resp", string(resp.Result))
	}
}
