package flashbotsextra

import (
	"context"
	"math/big"
	"time"

	apiv1 "github.com/attestantio/go-builder-client/api/v1"
	builderApiV1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

const (
	highPrioLimitSize = 500
	lowPrioLimitSize  = 100
)

type BlockConsumer interface {
	ConsumeBuiltBlock(block *types.Block, blockValue *big.Int, OrdersClosedAt time.Time, sealedAt time.Time, commitedBundles []types.SimulatedBundle, allBundles []types.SimulatedBundle, usedSbundles []types.UsedSBundle, bidTrace *builderApiV1.BidTrace) error
}
type IDatabaseService interface {
	GetPriorityBundles(ctx context.Context, blockNum int64, isHighPrio bool) ([]DbBundle, error)
	GetLatestUuidBundles(ctx context.Context, blockNum int64) ([]types.LatestUuidBundle, error)
}

type NilDbService struct{}

func (NilDbService) ConsumeBuiltBlock(block *types.Block, blockValue *big.Int, OrdersClosedAt time.Time, sealedAt time.Time, commitedBundles []types.SimulatedBundle, allBundles []types.SimulatedBundle, usedSbundles []types.UsedSBundle, bidTrace *apiv1.BidTrace) error {
	return nil
}

func (NilDbService) GetPriorityBundles(ctx context.Context, blockNum int64, isHighPrio bool) ([]DbBundle, error) {
	return []DbBundle{}, nil
}

func (NilDbService) GetLatestUuidBundles(ctx context.Context, blockNum int64) ([]types.LatestUuidBundle, error) {
	return []types.LatestUuidBundle{}, nil
}

type DatabaseService struct {
	db *sqlx.DB

	insertMissingBundleStmt       *sqlx.NamedStmt
	fetchPrioBundlesStmt          *sqlx.NamedStmt
	fetchGetLatestUuidBundlesStmt *sqlx.NamedStmt
}

func NewDatabaseService(postgresDSN string) (*DatabaseService, error) {
	db, err := sqlx.Connect("postgres", postgresDSN)
	if err != nil {
		return nil, err
	}

	insertMissingBundleStmt, err := db.PrepareNamed("insert into bundles (bundle_hash, param_signed_txs, param_block_number, param_timestamp, received_timestamp, param_reverting_tx_hashes, coinbase_diff, total_gas_used, state_block_number, gas_fees, eth_sent_to_coinbase, bundle_uuid) values (:bundle_hash, :param_signed_txs, :param_block_number, :param_timestamp, :received_timestamp, :param_reverting_tx_hashes, :coinbase_diff, :total_gas_used, :state_block_number, :gas_fees, :eth_sent_to_coinbase, :bundle_uuid) on conflict do nothing returning id")
	if err != nil {
		return nil, err
	}

	fetchPrioBundlesStmt, err := db.PrepareNamed("select bundle_hash, param_signed_txs, param_block_number, param_timestamp, received_timestamp, param_reverting_tx_hashes, coinbase_diff, total_gas_used, state_block_number, gas_fees, eth_sent_to_coinbase, bundle_uuid from bundles where is_high_prio = :is_high_prio and coinbase_diff*1e18/total_gas_used > 1000000000 and param_block_number = :param_block_number order by coinbase_diff/total_gas_used DESC limit :limit")
	if err != nil {
		return nil, err
	}

	fetchGetLatestUuidBundlesStmt, err := db.PrepareNamed("select replacement_uuid, signing_address, bundle_hash, bundle_uuid from latest_uuid_bundle where target_block_number = :target_block_number")
	if err != nil {
		return nil, err
	}

	return &DatabaseService{
		db:                            db,
		insertMissingBundleStmt:       insertMissingBundleStmt,
		fetchPrioBundlesStmt:          fetchPrioBundlesStmt,
		fetchGetLatestUuidBundlesStmt: fetchGetLatestUuidBundlesStmt,
	}, nil
}

func Min(l, r int) int {
	if l < r {
		return l
	}
	return r
}

func (ds *DatabaseService) GetPriorityBundles(ctx context.Context, blockNum int64, isHighPrio bool) ([]DbBundle, error) {
	var bundles []DbBundle
	arg := map[string]interface{}{"param_block_number": uint64(blockNum), "is_high_prio": isHighPrio, "limit": lowPrioLimitSize}
	if isHighPrio {
		arg["limit"] = highPrioLimitSize
	}
	if err := ds.fetchPrioBundlesStmt.SelectContext(ctx, &bundles, arg); err != nil {
		return nil, err
	}
	return bundles, nil
}

func (ds *DatabaseService) GetLatestUuidBundles(ctx context.Context, blockNum int64) ([]types.LatestUuidBundle, error) {
	var dstLatestBundles []DbLatestUuidBundle
	kwArg := map[string]interface{}{"target_block_number": blockNum}
	if err := ds.fetchGetLatestUuidBundlesStmt.SelectContext(ctx, &dstLatestBundles, kwArg); err != nil {
		return nil, err
	}
	latestBundles := make([]types.LatestUuidBundle, 0, len(dstLatestBundles))
	for _, dbLub := range dstLatestBundles {
		latestBundles = append(latestBundles, types.LatestUuidBundle{
			Uuid:           dbLub.Uuid,
			SigningAddress: common.HexToAddress(dbLub.SigningAddress),
			BundleHash:     common.HexToHash(dbLub.BundleHash),
			BundleUUID:     dbLub.BundleUUID,
		})
	}
	return latestBundles, nil
}
