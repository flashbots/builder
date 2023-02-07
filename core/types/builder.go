package types

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

type BuilderPayloadAttributes struct {
	Timestamp             hexutil.Uint64 `json:"timestamp"`
	Random                common.Hash    `json:"prevRandao"`
	SuggestedFeeRecipient common.Address `json:"suggestedFeeRecipient,omitempty"`
	Slot                  uint64         `json:"slot"`
	HeadHash              common.Hash    `json:"blockHash"`
	Withdrawals           Withdrawals    `json:"withdrawals"`
	GasLimit              uint64
}
