package flashbotsextra

import (
	"context"
	"database/sql"
	"math/big"
	"time"

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
	ConsumeBuiltBlock(block *types.Block, bundles []types.SimulatedBundle, bidTrace *boostTypes.BidTrace)
	GetPriorityBundles(ctx context.Context, blockNum int64, isHighPrio bool) ([]DbBundle, error)
}

type NilDbService struct{}

func (NilDbService) ConsumeBuiltBlock(*types.Block, []types.SimulatedBundle, *boostTypes.BidTrace) {}

func (NilDbService) GetPriorityBundles(ctx context.Context, blockNum int64, isHighPrio bool) ([]DbBundle, error) {
	return []DbBundle{}, nil
}

type DatabaseService struct {
	db *sqlx.DB

	insertBuiltBlockStmt             *sqlx.NamedStmt
	insertBlockBuiltBundleNoIdStmt   *sqlx.NamedStmt
	insertBlockBuiltBundleWithIdStmt *sqlx.NamedStmt
	insertMissingBundleStmt          *sqlx.NamedStmt
	fetchPrioBundlesStmt             *sqlx.NamedStmt
}

func NewDatabaseService(postgresDSN string) (*DatabaseService, error) {
	db, err := sqlx.Connect("postgres", postgresDSN)
	if err != nil {
		return nil, err
	}

	insertBuiltBlockStmt, err := db.PrepareNamed("insert into built_blocks (block_number, profit, slot, hash, gas_limit, gas_used, base_fee, parent_hash, proposer_pubkey, proposer_fee_recipient, builder_pubkey, timestamp, timestamp_datetime) values (:block_number, :profit, :slot, :hash, :gas_limit, :gas_used, :base_fee, :parent_hash, :proposer_pubkey, :proposer_fee_recipient, :builder_pubkey, :timestamp, to_timestamp(:timestamp)) returning block_id")
	if err != nil {
		return nil, err
	}

	insertBlockBuiltBundleNoIdStmt, err := db.PrepareNamed("insert into built_blocks_bundles (block_id, bundle_id) select :block_id, id from bundles where bundle_hash = :bundle_hash and param_block_number = :block_number returning bundle_id")
	if err != nil {
		return nil, err
	}

	insertBlockBuiltBundleWithIdStmt, err := db.PrepareNamed("insert into built_blocks_bundles (block_id, bundle_id) select :block_id, :bundle_id returning bundle_id")
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
	return &DatabaseService{
		db:                               db,
		insertBuiltBlockStmt:             insertBuiltBlockStmt,
		insertBlockBuiltBundleNoIdStmt:   insertBlockBuiltBundleNoIdStmt,
		insertBlockBuiltBundleWithIdStmt: insertBlockBuiltBundleWithIdStmt,
		insertMissingBundleStmt:          insertMissingBundleStmt,
		fetchPrioBundlesStmt:             fetchPrioBundlesStmt,
	}, nil
}

func (ds *DatabaseService) ConsumeBuiltBlock(block *types.Block, bundles []types.SimulatedBundle, bidTrace *boostTypes.BidTrace) {
	tx, err := ds.db.Beginx()
	if err != nil {
		log.Error("could not insert built block", "err", err)
		return
	}

	blockData := BuiltBlock{
		BlockNumber:          block.NumberU64(),
		Profit:               new(big.Rat).SetFrac(block.Profit, big.NewInt(1e18)).FloatString(18),
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
	}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	var blockId uint64
	if err = tx.NamedStmtContext(ctx, ds.insertBuiltBlockStmt).GetContext(ctx, &blockId, blockData); err != nil {
		log.Error("could not insert built block", "err", err)
		tx.Rollback()
		return
	}

	for _, bundle := range bundles {
		bundleData := BuiltBlockBundle{
			BlockId:     blockId,
			BundleId:    nil,
			BlockNumber: blockData.BlockNumber,
			BundleHash:  bundle.OriginalBundle.Hash.String(),
		}

		var bundleId uint64
		err := tx.NamedStmtContext(ctx, ds.insertBlockBuiltBundleNoIdStmt).GetContext(ctx, &bundleId, bundleData)
		if err == nil {
			continue
		}

		if err != sql.ErrNoRows {
			log.Error("could not insert bundle", "err", err)
			// Try anyway
		}

		missingBundleData := SimulatedBundleToDbBundle(&bundle)
		err = ds.insertMissingBundleStmt.GetContext(ctx, &bundleId, missingBundleData) // not using the tx as it relies on the unique constraint!
		if err == nil {
			bundleData.BundleId = &bundleId
			_, err = tx.NamedStmtContext(ctx, ds.insertBlockBuiltBundleWithIdStmt).ExecContext(ctx, bundleData)
			if err != nil {
				log.Error("could not insert built block bundle after inserting missing bundle", "err", err)
			}
		} else if err == sql.ErrNoRows /* conflict, someone else inserted the bundle before we could */ {
			if err := tx.NamedStmtContext(ctx, ds.insertBlockBuiltBundleNoIdStmt).GetContext(ctx, &bundleId, bundleData); err != nil {
				log.Error("could not insert bundle on retry", "err", err)
				continue
			}
		} else {
			log.Error("could not insert missing bundle", "err", err)
		}
	}

	err = tx.Commit()
	if err != nil {
		log.Error("could not commit DB trasnaction", "err", err)
	}
}
func (ds *DatabaseService) GetPriorityBundles(ctx context.Context, blockNum int64, isHighPrio bool) ([]DbBundle, error) {
	var bundles []DbBundle
	tx, err := ds.db.Beginx()
	if err != nil {
		log.Error("failed to begin db tx for get priority bundles", "err", err)
		return nil, err
	}
	arg := map[string]interface{}{"param_block_number": uint64(blockNum), "is_high_prio": isHighPrio, "limit": lowPrioLimitSize}
	if isHighPrio {
		arg["limit"] = highPrioLimitSize
	}
	if err = tx.NamedStmtContext(ctx, ds.fetchPrioBundlesStmt).SelectContext(ctx, &bundles, arg); err != nil {
		return nil, err
	}
	err = tx.Commit()
	if err != nil {
		log.Error("could not commit GetPriorityBundles transaction", "err", err)
	}
	return bundles, nil
}
