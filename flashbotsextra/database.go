package flashbotsextra

import (
	"context"
	"database/sql"
	"math/big"
	"time"

	apiv1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

const (
	highPrioLimitSize = 500
	lowPrioLimitSize  = 100
)

type IDatabaseService interface {
	ConsumeBuiltBlock(block *types.Block, blockValue *big.Int, OrdersClosedAt time.Time, sealedAt time.Time,
		commitedBundles []types.SimulatedBundle, allBundles []types.SimulatedBundle,
		usedSbundles []types.UsedSBundle,
		bidTrace *apiv1.BidTrace)
	GetPriorityBundles(ctx context.Context, blockNum int64, isHighPrio bool) ([]DbBundle, error)
	GetLatestUuidBundles(ctx context.Context, blockNum int64) ([]types.LatestUuidBundle, error)
}

type NilDbService struct{}

func (NilDbService) ConsumeBuiltBlock(block *types.Block, _ *big.Int, _ time.Time, _ time.Time, _ []types.SimulatedBundle, _ []types.SimulatedBundle, _ []types.UsedSBundle, _ *apiv1.BidTrace) {
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

func (ds *DatabaseService) getBundleIds(ctx context.Context, blockNumber uint64, bundles []uuidBundle) (map[uuid.UUID]uint64, error) {
	if len(bundles) == 0 {
		return nil, nil
	}

	bundleIdsMap := make(map[uuid.UUID]uint64, len(bundles))

	// Batch by 500
	requestsToMake := [][]string{make([]string, 0, Min(500, len(bundles)))}
	cRequestInd := 0
	for i, bundle := range bundles {
		if i != 0 && i%500 == 0 {
			cRequestInd += 1
			requestsToMake = append(requestsToMake, make([]string, 0, Min(500, len(bundles)-i)))
		}
		requestsToMake[cRequestInd] = append(requestsToMake[cRequestInd], bundle.SimulatedBundle.OriginalBundle.Hash.String())
	}

	for _, request := range requestsToMake {
		query, args, err := sqlx.In("select id, bundle_hash, bundle_uuid from bundles where param_block_number = ? and bundle_hash in (?)", blockNumber, request)
		if err != nil {
			return nil, err
		}
		query = ds.db.Rebind(query)

		queryRes := []struct {
			Id         uint64    `db:"id"`
			BundleHash string    `db:"bundle_hash"`
			BundleUUID uuid.UUID `db:"bundle_uuid"`
		}{}

		err = ds.db.SelectContext(ctx, &queryRes, query, args...)
		if err != nil {
			return nil, err
		}
	RowLoop:
		for _, row := range queryRes {
			for _, b := range bundles {
				// if UUID agree it's same exact bundle we stop searching
				if b.UUID == row.BundleUUID {
					bundleIdsMap[b.UUID] = row.Id
					continue RowLoop
				}
				// we can have multiple bundles with same hash eventually, so we fall back on getting row with same hash
				if b.SimulatedBundle.OriginalBundle.Hash.String() == row.BundleHash {
					bundleIdsMap[b.UUID] = row.Id
				}
			}
		}
	}

	return bundleIdsMap, nil
}

// TODO: cache locally for current block!
func (ds *DatabaseService) getBundleIdsAndInsertMissingBundles(ctx context.Context, blockNumber uint64, bundles []uuidBundle) (map[uuid.UUID]uint64, error) {
	bundleIdsMap, err := ds.getBundleIds(ctx, blockNumber, bundles)
	if err != nil {
		return nil, err
	}

	toRetry := make([]uuidBundle, 0)
	for _, bundle := range bundles {
		if _, found := bundleIdsMap[bundle.UUID]; found {
			continue
		}

		var bundleId uint64
		missingBundleData := SimulatedBundleToDbBundle(&bundle.SimulatedBundle)        // nolint: gosec
		err = ds.insertMissingBundleStmt.GetContext(ctx, &bundleId, missingBundleData) // not using the tx as it relies on the unique constraint!
		if err == nil {
			bundleIdsMap[bundle.UUID] = bundleId
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

func (ds *DatabaseService) insertBuildBlock(tx *sqlx.Tx, ctx context.Context, block *types.Block, blockValue *big.Int, bidTrace *apiv1.BidTrace, ordersClosedAt time.Time, sealedAt time.Time) (uint64, error) {
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

func (ds *DatabaseService) insertAllBlockBundleIds(tx *sqlx.Tx, ctx context.Context, blockId uint64, bundleIds []uint64) error {
	if len(bundleIds) == 0 {
		return nil
	}

	toInsert := make([]blockAndBundleId, 0, len(bundleIds))
	for _, bundleId := range bundleIds {
		toInsert = append(toInsert, blockAndBundleId{blockId, bundleId})
	}

	_, err := tx.NamedExecContext(ctx, "insert into built_blocks_all_bundles (block_id, bundle_id) values (:block_id, :bundle_id)", toInsert)
	return err
}

func (ds *DatabaseService) insertUsedSBundleIds(tx *sqlx.Tx, ctx context.Context, blockId uint64, usedSbundles []types.UsedSBundle) error {
	if len(usedSbundles) == 0 {
		return nil
	}

	toInsert := make([]DbUsedSBundle, len(usedSbundles))
	for i, u := range usedSbundles {
		toInsert[i] = DbUsedSBundle{
			BlockId:  blockId,
			Hash:     u.Bundle.Hash().Bytes(),
			Inserted: u.Success,
		}
	}
	_, err := tx.NamedExecContext(ctx, insertUsedSbundleQuery, toInsert)
	return err
}

type uuidBundle struct {
	SimulatedBundle types.SimulatedBundle
	UUID            uuid.UUID
}

func (ds *DatabaseService) ConsumeBuiltBlock(block *types.Block, blockValue *big.Int, ordersClosedAt time.Time, sealedAt time.Time,
	commitedBundles []types.SimulatedBundle, allBundles []types.SimulatedBundle,
	usedSbundles []types.UsedSBundle,
	bidTrace *apiv1.BidTrace) {
	var allUUIDBundles = make([]uuidBundle, 0, len(allBundles))
	for _, bundle := range allBundles {
		allUUIDBundles = append(allUUIDBundles, uuidBundle{bundle, bundle.OriginalBundle.ComputeUUID()})
	}

	var commitedUUIDBundles = make([]uuidBundle, 0, len(commitedBundles))
	for _, bundle := range commitedBundles {
		commitedUUIDBundles = append(commitedUUIDBundles, uuidBundle{bundle, bundle.OriginalBundle.ComputeUUID()})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	bundleIdsMap, err := ds.getBundleIdsAndInsertMissingBundles(ctx, block.NumberU64(), allUUIDBundles)
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
	for _, bundle := range commitedUUIDBundles {
		if id, found := bundleIdsMap[bundle.UUID]; found {
			commitedBundlesIds = append(commitedBundlesIds, id)
		}
	}

	err = ds.insertBuildBlockBundleIds(tx, ctx, blockId, commitedBundlesIds)
	if err != nil {
		tx.Rollback()
		log.Error("could not insert built block bundles", "err", err)
		return
	}

	var uniqueBundleIDs = make(map[uint64]struct{})
	var allBundleIds []uint64
	// we need to filter out duplicates while we still have unique constraint on bundle_hash+block_number which leads to data discrepancies
	for _, v := range bundleIdsMap {
		if _, ok := uniqueBundleIDs[v]; ok {
			continue
		}
		uniqueBundleIDs[v] = struct{}{}
		allBundleIds = append(allBundleIds, v)
	}
	err = ds.insertAllBlockBundleIds(tx, ctx, blockId, allBundleIds)
	if err != nil {
		tx.Rollback()
		log.Error("could not insert built block all bundles", "err", err, "block", block.NumberU64(), "commitedBundles", commitedBundlesIds)
		return
	}

	err = ds.insertUsedSBundleIds(tx, ctx, blockId, usedSbundles)
	if err != nil {
		tx.Rollback()
		log.Error("could not insert used sbundles", "err", err)
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
			BundleUUID:     dbLub.BundleUUID,
		})
	}
	return latestBundles, nil
}
