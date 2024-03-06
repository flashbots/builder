package flashbotsextra

import (
	"time"

	"github.com/google/uuid"
)

type BuiltBlock struct {
	BlockId              uint64    `db:"block_id"`
	BlockNumber          uint64    `db:"block_number"`
	Profit               string    `db:"profit"`
	Slot                 uint64    `db:"slot"`
	Hash                 string    `db:"hash"`
	GasLimit             uint64    `db:"gas_limit"`
	GasUsed              uint64    `db:"gas_used"`
	BaseFee              uint64    `db:"base_fee"`
	ParentHash           string    `db:"parent_hash"`
	ProposerPubkey       string    `db:"proposer_pubkey"`
	ProposerFeeRecipient string    `db:"proposer_fee_recipient"`
	BuilderPubkey        string    `db:"builder_pubkey"`
	Timestamp            uint64    `db:"timestamp"`
	TimestampDatetime    time.Time `db:"timestamp_datetime"`
	OrdersClosedAt       time.Time `db:"orders_closed_at"`
	SealedAt             time.Time `db:"sealed_at"`
}

type BuiltBlockBundle struct {
	BlockId     uint64  `db:"block_id"`
	BundleId    *uint64 `db:"bundle_id"`
	BlockNumber uint64  `db:"block_number"`
	BundleHash  string  `db:"bundle_hash"`
}

type DbBundle struct {
	DbId       uint64    `db:"id"`
	BundleHash string    `db:"bundle_hash"`
	BundleUUID uuid.UUID `db:"bundle_uuid"`

	ParamSignedTxs         string    `db:"param_signed_txs"`
	ParamBlockNumber       uint64    `db:"param_block_number"`
	ParamTimestamp         *uint64   `db:"param_timestamp"`
	ReceivedTimestamp      time.Time `db:"received_timestamp"`
	ParamRevertingTxHashes *string   `db:"param_reverting_tx_hashes"`

	CoinbaseDiff      string `db:"coinbase_diff"`
	TotalGasUsed      uint64 `db:"total_gas_used"`
	StateBlockNumber  uint64 `db:"state_block_number"`
	GasFees           string `db:"gas_fees"`
	EthSentToCoinbase string `db:"eth_sent_to_coinbase"`
}

type DbLatestUuidBundle struct {
	Uuid           uuid.UUID `db:"replacement_uuid"`
	SigningAddress string    `db:"signing_address"`
	BundleHash     string    `db:"bundle_hash"`
	BundleUUID     uuid.UUID `db:"bundle_uuid"`
}

type DbUsedSBundle struct {
	BlockId  uint64 `db:"block_id"`
	Hash     []byte `db:"hash"`
	Inserted bool   `db:"inserted"`
}
