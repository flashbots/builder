package flashbotsextra

import (
	"context"
	"database/sql"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	boostTypes "github.com/flashbots/go-boost-utils/types"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

const (
	highPrioLimitSize = 500
	lowPrioLimitSize  = 100
)

type IDatabaseService interface {
	ConsumeBuiltBlock(block *types.Block, blockValue *big.Int, OrdersClosedAt time.Time, sealedAt time.Time, commitedBundles []types.SimulatedBundle, allBundles []types.SimulatedBundle, bidTrace *boostTypes.BidTrace)
	GetPriorityBundles(ctx context.Context, blockNum int64, isHighPrio bool) ([]DbBundle, error)
	GetLatestUuidBundles(ctx context.Context, blockNum int64) ([]types.LatestUuidBundle, error)
}

type NilDbService struct{}

func (NilDbService) ConsumeBuiltBlock(block *types.Block, _ *big.Int, _ time.Time, _ time.Time, _ []types.SimulatedBundle, _ []types.SimulatedBundle, _ *boostTypes.BidTrace) {
}

func (NilDbService) GetPriorityBundles(ctx context.Context, blockNum int64, isHighPrio bool) ([]DbBundle, error) {
	return []DbBundle{}, nil
}

func (NilDbService) GetLatestUuidBundles(ctx context.Context, blockNum int64) ([]types.LatestUuidBundle, error) {
	return []types.LatestUuidBundle{}, nil
}

type DatabaseService struct {
	db *sqlx.DB

	insertBuiltBlockStmt          *sqlx.NamedStmt
	insertMissingBundleStmt       *sqlx.NamedStmt
	fetchPrioBundlesStmt          *sqlx.NamedStmt
	fetchGetLatestUuidBundlesStmt *sqlx.NamedStmt
}

func NewDatabaseService(postgresDSN string) (*DatabaseService, error) {
	db, err := sqlx.Connect("postgres", postgresDSN)
	if err != nil {
		return nil, err
	}

	insertBuiltBlockStmt, err := db.PrepareNamed("insert into built_blocks (block_number, profit, slot, hash, gas_limit, gas_used, base_fee, parent_hash, proposer_pubkey, proposer_fee_recipient, builder_pubkey, timestamp, timestamp_datetime, orders_closed_at, sealed_at) values (:block_number, :profit, :slot, :hash, :gas_limit, :gas_used, :base_fee, :parent_hash, :proposer_pubkey, :proposer_fee_recipient, :builder_pubkey, :timestamp, to_timestamp(:timestamp), :orders_closed_at, :sealed_at) returning block_id")
	if err != nil {
		return nil, err
	}

	insertMissingBundleStmt, err := db.PrepareNamed("insert into bundles (bundle_hash, param_signed_txs, param_block_number, param_timestamp, received_timestamp, param_reverting_tx_hashes, coinbase_diff, total_gas_used, state_block_number, gas_fees, eth_sent_to_coinbase) values (:bundle_hash, :param_signed_txs, :param_block_number, :param_timestamp, :received_timestamp, :param_reverting_tx_hashes, :coinbase_diff, :total_gas_used, :state_block_number, :gas_fees, :eth_sent_to_coinbase) on conflict (bundle_hash, param_block_number) do nothing returning id")
	if err != nil {
		return nil, err
	}

	fetchPrioBundlesStmt, err := db.PrepareNamed("select bundle_hash, param_signed_txs, param_block_number, param_timestamp, received_timestamp, param_reverting_tx_hashes, coinbase_diff, total_gas_used, state_block_number, gas_fees, eth_sent_to_coinbase from bundles where is_high_prio = :is_high_prio and coinbase_diff*1e18/total_gas_used > 1000000000 and param_block_number = :param_block_number order by coinbase_diff/total_gas_used DESC limit :limit")
	if err != nil {
		return nil, err
	}

	fetchGetLatestUuidBundlesStmt, err := db.PrepareNamed("select replacement_uuid, signing_address, bundle_hash from latest_uuid_bundle where target_block_number = :target_block_number")
	if err != nil {
		return nil, err
	}

	return &DatabaseService{
		db:                            db,
		insertBuiltBlockStmt:          insertBuiltBlockStmt,
		insertMissingBundleStmt:       insertMissingBundleStmt,
		fetchPrioBundlesStmt:          fetchPrioBundlesStmt,
		fetchGetLatestUuidBundlesStmt: fetchGetLatestUuidBundlesStmt,
	}, nil
}

func Min(l int, r int) int {
	if l < r {
		return l
	}
	return r
}

func (ds *DatabaseService) getBundleIds(ctx context.Context, blockNumber uint64, bundles []types.SimulatedBundle) (map[string]uint64, error) {
	if len(bundles) == 0 {
		return nil, nil
	}

	bundleIdsMap := make(map[string]uint64, len(bundles))

	// Batch by 500
	requestsToMake := [][]string{make([]string, 0, Min(500, len(bundles)))}
	cRequestInd := 0
	for i, bundle := range bundles {
		if i != 0 && i%500 == 0 {
			cRequestInd += 1
			requestsToMake = append(requestsToMake, make([]string, 0, Min(500, len(bundles)-i)))
		}
		requestsToMake[cRequestInd] = append(requestsToMake[cRequestInd], bundle.OriginalBundle.Hash.String())
	}

	for _, request := range requestsToMake {
		query, args, err := sqlx.In("select id, bundle_hash from bundles where param_block_number = ? and bundle_hash in (?)", blockNumber, request)
		if err != nil {
			return nil, err
		}
		query = ds.db.Rebind(query)

		queryRes := []struct {
			Id         uint64 `db:"id"`
			BundleHash string `db:"bundle_hash"`
		}{}
		err = ds.db.SelectContext(ctx, &queryRes, query, args...)
		if err != nil {
			return nil, err
		}

		for _, row := range queryRes {
			bundleIdsMap[row.BundleHash] = row.Id
		}
	}

	return bundleIdsMap, nil
}

// TODO: cache locally for current block!
func (ds *DatabaseService) getBundleIdsAndInsertMissingBundles(ctx context.Context, blockNumber uint64, bundles []types.SimulatedBundle) (map[string]uint64, error) {
	bundleIdsMap, err := ds.getBundleIds(ctx, blockNumber, bundles)
	if err != nil {
		return nil, err
	}

	toRetry := []types.SimulatedBundle{}
	for _, bundle := range bundles {
		bundleHashString := bundle.OriginalBundle.Hash.String()
		if _, found := bundleIdsMap[bundleHashString]; found {
			continue
		}

		var bundleId uint64
		missingBundleData := SimulatedBundleToDbBundle(&bundle)                        // nolint: gosec
		err = ds.insertMissingBundleStmt.GetContext(ctx, &bundleId, missingBundleData) // not using the tx as it relies on the unique constraint!
		if err == nil {
			bundleIdsMap[bundleHashString] = bundleId
		} else if err == sql.ErrNoRows /* conflict, someone else inserted the bundle before we could */ {
			toRetry = append(toRetry, bundle)
		} else {
			log.Error("could not insert missing bundle", "err", err)
		}
	}

	retriedBundleIds, err := ds.getBundleIds(ctx, blockNumber, toRetry)
	if err != nil {
		return nil, err
	}

	for hash, id := range retriedBundleIds {
		bundleIdsMap[hash] = id
	}

	return bundleIdsMap, nil
}

func (ds *DatabaseService) insertBuildBlock(tx *sqlx.Tx, ctx context.Context, block *types.Block, blockValue *big.Int, bidTrace *boostTypes.BidTrace, ordersClosedAt time.Time, sealedAt time.Time) (uint64, error) {
	blockData := BuiltBlock{
		BlockNumber:          block.NumberU64(),
		Profit:               new(big.Rat).SetFrac(blockValue, big.NewInt(1e18)).FloatString(18),
		Slot:                 bidTrace.Slot,
		Hash:                 block.Hash().String(),
		GasLimit:             block.GasLimit(),
		GasUsed:              block.GasUsed(),
		BaseFee:              block.BaseFee().Uint64(),
		ParentHash:           block.ParentHash().String(),
		ProposerPubkey:       bidTrace.ProposerPubkey.String(),
		ProposerFeeRecipient: bidTrace.ProposerFeeRecipient.String(),
		BuilderPubkey:        bidTrace.BuilderPubkey.String(),
		Timestamp:            block.Time(),
		OrdersClosedAt:       ordersClosedAt.UTC(),
		SealedAt:             sealedAt.UTC(),
	}

	var blockId uint64
	if err := tx.NamedStmtContext(ctx, ds.insertBuiltBlockStmt).GetContext(ctx, &blockId, blockData); err != nil {
		log.Error("could not insert built block", "err", err)
		return 0, err
	}

	return blockId, nil
}

func (ds *DatabaseService) insertBuildBlockBundleIds(tx *sqlx.Tx, ctx context.Context, blockId uint64, bundleIds []uint64) error {
	if len(bundleIds) == 0 {
		return nil
	}

	toInsert := make([]blockAndBundleId, len(bundleIds))
	for i, bundleId := range bundleIds {
		toInsert[i] = blockAndBundleId{blockId, bundleId}
	}

	_, err := tx.NamedExecContext(ctx, "insert into built_blocks_bundles (block_id, bundle_id) values (:block_id, :bundle_id)", toInsert)
	return err
}

func (ds *DatabaseService) insertAllBlockBundleIds(tx *sqlx.Tx, ctx context.Context, blockId uint64, bundleIdsMap map[string]uint64) error {
	if len(bundleIdsMap) == 0 {
		return nil
	}

	toInsert := make([]blockAndBundleId, 0, len(bundleIdsMap))
	for _, bundleId := range bundleIdsMap {
		toInsert = append(toInsert, blockAndBundleId{blockId, bundleId})
	}

	_, err := tx.NamedExecContext(ctx, "insert into built_blocks_all_bundles (block_id, bundle_id) values (:block_id, :bundle_id)", toInsert)
	return err
}

func (ds *DatabaseService) ConsumeBuiltBlock(block *types.Block, blockValue *big.Int, ordersClosedAt time.Time, sealedAt time.Time, commitedBundles []types.SimulatedBundle, allBundles []types.SimulatedBundle, bidTrace *boostTypes.BidTrace) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	bundleIdsMap, err := ds.getBundleIdsAndInsertMissingBundles(ctx, block.NumberU64(), allBundles)
	if err != nil {
		log.Error("could not insert bundles", "err", err)
	}

	tx, err := ds.db.Beginx()
	if err != nil {
		log.Error("could not open DB transaction", "err", err)
		return
	}

	blockId, err := ds.insertBuildBlock(tx, ctx, block, blockValue, bidTrace, ordersClosedAt, sealedAt)
	if err != nil {
		tx.Rollback()
		log.Error("could not insert built block", "err", err)
		return
	}

	commitedBundlesIds := make([]uint64, 0, len(commitedBundles))
	for _, bundle := range commitedBundles {
		if id, found := bundleIdsMap[bundle.OriginalBundle.Hash.String()]; found {
			commitedBundlesIds = append(commitedBundlesIds, id)
		}
	}

	err = ds.insertBuildBlockBundleIds(tx, ctx, blockId, commitedBundlesIds)
	if err != nil {
		tx.Rollback()
		log.Error("could not insert built block bundles", "err", err)
		return
	}

	err = ds.insertAllBlockBundleIds(tx, ctx, blockId, bundleIdsMap)
	if err != nil {
		tx.Rollback()
		log.Error("could not insert built block all bundles", "err", err)
		return
	}

	err = tx.Commit()
	if err != nil {
		log.Error("could not commit DB trasnaction", "err", err)
	}
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
		})
	}
	return latestBundles, nil
}
