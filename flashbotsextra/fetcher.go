package flashbotsextra

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/log"
	"golang.org/x/crypto/sha3"
)

type Fetcher interface {
	Run() error
}

type bundleFetcher struct {
	db                 IDatabaseService
	backend            *eth.Ethereum
	blockNumCh         chan int64
	bundlesCh          chan []types.MevBundle
	shouldPushToTxPool bool // Added for testing
}

func NewBundleFetcher(backend *eth.Ethereum, db IDatabaseService, blockNumCh chan int64, bundlesCh chan []types.MevBundle, shouldPushToTxPool bool) *bundleFetcher {
	return &bundleFetcher{
		db:                 db,
		backend:            backend,
		blockNumCh:         blockNumCh,
		bundlesCh:          bundlesCh,
		shouldPushToTxPool: shouldPushToTxPool,
	}
}

func (b *bundleFetcher) Run() {
	log.Info("Start bundle fetcher")
	if b.shouldPushToTxPool {
		eventCh := make(chan core.ChainHeadEvent)
		b.backend.BlockChain().SubscribeChainHeadEvent(eventCh)
		pushBlockNum := func() {
			for currentBlockNum := range eventCh {
				b.blockNumCh <- currentBlockNum.Block.Header().Number.Int64()
			}
		}
		addMevBundle := func() {
			log.Info("Start receiving mev bundles")
			for bundles := range b.bundlesCh {
				b.backend.TxPool().AddMevBundles(bundles)
			}
		}
		go pushBlockNum()
		go addMevBundle()
	}
	pushMevBundles := func(bundles []DbBundle) {
		mevBundles := make([]types.MevBundle, 0)
		for _, bundle := range bundles {
			mevBundle, err := b.dbBundleToMevBundle(bundle)
			if err != nil {
				log.Error("failed to convert db bundle to mev bundle", "err", err)
				continue
			}
			mevBundles = append(mevBundles, *mevBundle)
		}
		if len(mevBundles) > 0 {
			b.bundlesCh <- mevBundles
		}
	}
	go b.fetchAndPush(context.Background(), pushMevBundles)
}

func (b *bundleFetcher) GetLatestUuidBundles(ctx context.Context, blockNum int64) ([]types.LatestUuidBundle, error) {
	return b.db.GetLatestUuidBundles(ctx, blockNum)
}

func (b *bundleFetcher) fetchAndPush(ctx context.Context, pushMevBundles func(bundles []DbBundle)) {
	var currentBlockNum int64
	lowPrioBundleTicker := time.NewTicker(time.Second * 2)
	defer lowPrioBundleTicker.Stop()

	for {
		select {
		case currentBlockNum = <-b.blockNumCh:
			ctxH, cancelH := context.WithTimeout(ctx, time.Second*3)
			bundles, err := b.db.GetPriorityBundles(ctxH, currentBlockNum+1, true)
			cancelH()
			if err != nil {
				log.Error("failed to fetch high prio bundles", "err", err)
				continue
			}
			log.Debug("Fetching High prio bundles", "size", len(bundles), "currentlyBuiltBlockNum", currentBlockNum+1)
			if len(bundles) != 0 {
				pushMevBundles(bundles)
			}

		case <-lowPrioBundleTicker.C:
			if currentBlockNum == 0 {
				continue
			}
			ctxL, cancelL := context.WithTimeout(ctx, time.Second*3)
			bundles, err := b.db.GetPriorityBundles(ctxL, currentBlockNum+1, false)
			cancelL()
			if err != nil {
				log.Error("failed to fetch low prio bundles", "err", err)
				continue
			}
			log.Debug("Fetching low prio bundles", "len", len(bundles), "currentlyBuiltBlockNum", currentBlockNum+1)
			if len(bundles) != 0 {
				pushMevBundles(bundles)
			}
		case <-ctx.Done():
			close(b.bundlesCh)
			return
		}
	}
}

func (b *bundleFetcher) dbBundleToMevBundle(arg DbBundle) (*types.MevBundle, error) {
	signedTxsStr := strings.Split(arg.ParamSignedTxs, ",")
	if len(signedTxsStr) == 0 {
		return nil, errors.New("bundle missing txs")
	}
	if arg.ParamBlockNumber == 0 {
		return nil, errors.New("bundle missing blockNumber")
	}

	var txs types.Transactions
	for _, txStr := range signedTxsStr {
		decodedTx, err := hexutil.Decode(txStr)
		if err != nil {
			log.Error("could not decode bundle tx", "id", arg.DbId, "err", err)
			continue
		}
		tx := new(types.Transaction)
		if err := tx.UnmarshalBinary(decodedTx); err != nil {
			log.Error("could not unmarshal bundle decoded tx", "id", arg.DbId, "err", err)
			continue
		}
		txs = append(txs, tx)
	}
	var paramRevertingTxHashes []string
	if arg.ParamRevertingTxHashes != nil {
		paramRevertingTxHashes = strings.Split(*arg.ParamRevertingTxHashes, ",")
	}
	revertingTxHashesStrings := paramRevertingTxHashes
	revertingTxHashes := make([]common.Hash, len(revertingTxHashesStrings))
	for _, rTxHashStr := range revertingTxHashesStrings {
		revertingTxHashes = append(revertingTxHashes, common.HexToHash(rTxHashStr))
	}
	var minTimestamp uint64
	if arg.ParamTimestamp != nil {
		minTimestamp = *arg.ParamTimestamp
	}
	bundleHasher := sha3.NewLegacyKeccak256()
	for _, tx := range txs {
		bundleHasher.Write(tx.Hash().Bytes())
	}
	bundleHash := common.BytesToHash(bundleHasher.Sum(nil))
	return &types.MevBundle{
		Txs:               txs,
		BlockNumber:       new(big.Int).SetUint64(arg.ParamBlockNumber),
		MinTimestamp:      minTimestamp,
		RevertingTxHashes: revertingTxHashes,
		Hash:              bundleHash,
	}, nil
}
