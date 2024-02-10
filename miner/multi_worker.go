package miner

import (
	"errors"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
)

type multiWorker struct {
	workers       []*worker
	regularWorker *worker
}

func (w *multiWorker) setSyncing(syncing bool) {
	for _, worker := range w.workers {
		worker.syncing.Store(syncing)
	}
}

func (w *multiWorker) stop() {
	for _, worker := range w.workers {
		worker.stop()
	}
}

func (w *multiWorker) start() {
	for _, worker := range w.workers {
		worker.start()
	}
}

func (w *multiWorker) close() {
	for _, worker := range w.workers {
		worker.close()
	}
}

func (w *multiWorker) isRunning() bool {
	for _, worker := range w.workers {
		if worker.isRunning() {
			return true
		}
	}
	return false
}

// pendingBlockAndReceipts returns pending block and corresponding receipts from the `regularWorker`
func (w *multiWorker) pendingBlockAndReceipts() (*types.Block, types.Receipts) {
	// return a snapshot to avoid contention on currentMu mutex
	return w.regularWorker.pendingBlockAndReceipts()
}

func (w *multiWorker) setGasCeil(ceil uint64) {
	for _, worker := range w.workers {
		worker.setGasCeil(ceil)
	}
}

func (w *multiWorker) setExtra(extra []byte) {
	for _, worker := range w.workers {
		worker.setExtra(extra)
	}
}

func (w *multiWorker) setRecommitInterval(interval time.Duration) {
	for _, worker := range w.workers {
		worker.setRecommitInterval(interval)
	}
}

func (w *multiWorker) setEtherbase(addr common.Address) {
	for _, worker := range w.workers {
		worker.setEtherbase(addr)
	}
}

func (w *multiWorker) setGasTip(tip *big.Int) {
	for _, worker := range w.workers {
		worker.setGasTip(tip)
	}
}

func (w *multiWorker) buildPayload(args *BuildPayloadArgs) (*Payload, error) {
	// Build the initial version with no transaction included. It should be fast
	// enough to run. The empty payload can at least make sure there is something
	// to deliver for not missing slot.
	var empty *newPayloadResult
	emptyParams := &generateParams{
		timestamp:   args.Timestamp,
		forceTime:   true,
		parentHash:  args.Parent,
		coinbase:    args.FeeRecipient,
		random:      args.Random,
		gasLimit:    args.GasLimit,
		withdrawals: args.Withdrawals,
		beaconRoot:  args.BeaconRoot,
		noTxs:       true,
	}
	for _, worker := range w.workers {
		empty = worker.getSealingBlock(emptyParams)
		if empty.err != nil {
			log.Error("could not start async block construction", "isFlashbotsWorker", worker.flashbots.isFlashbots, "#bundles", worker.flashbots.maxMergedBundles)
			continue
		}
		break
	}

	if empty == nil || empty.block == nil {
		return nil, errors.New("no worker could build an empty block")
	}

	// Construct a payload object for return.
	payload := newPayload(empty.block, args.Id())

	if len(w.workers) == 0 {
		return payload, nil
	}

	// Keep separate payloads for each worker so that ResolveFull actually resolves the best of all workers
	workerPayloads := []*Payload{}

	for _, w := range w.workers {
		workerPayload := newPayload(empty.block, args.Id())
		workerPayloads = append(workerPayloads, workerPayload)
		fullParams := &generateParams{
			timestamp:   args.Timestamp,
			forceTime:   true,
			parentHash:  args.Parent,
			coinbase:    args.FeeRecipient,
			random:      args.Random,
			withdrawals: args.Withdrawals,
			beaconRoot:  args.BeaconRoot,
			gasLimit:    args.GasLimit,
			noTxs:       false,
			onBlock:     args.BlockHook,
		}

		go func(w *worker) {
			// Update routine done elsewhere!
			start := time.Now()
			r := w.getSealingBlock(fullParams)
			if r.err == nil {
				workerPayload.update(r, time.Since(start))
			} else {
				log.Error("Error while sealing block", "err", r.err)
				workerPayload.Cancel()
			}
		}(w)
	}

	go payload.resolveBestFullPayload(workerPayloads)

	return payload, nil
}

func newMultiWorker(config *Config, chainConfig *params.ChainConfig, engine consensus.Engine, eth Backend, mux *event.TypeMux, isLocalBlock func(header *types.Header) bool, init bool) *multiWorker {
	switch config.AlgoType {
	case ALGO_MEV_GETH:
		return newMultiWorkerMevGeth(config, chainConfig, engine, eth, mux, isLocalBlock, init)
	case ALGO_GREEDY, ALGO_GREEDY_BUCKETS, ALGO_GREEDY_MULTISNAP, ALGO_GREEDY_BUCKETS_MULTISNAP:
		return newMultiWorkerGreedy(config, chainConfig, engine, eth, mux, isLocalBlock, init)
	default:
		panic("unsupported builder algorithm found")
	}
}

func newMultiWorkerGreedy(config *Config, chainConfig *params.ChainConfig, engine consensus.Engine, eth Backend, mux *event.TypeMux, isLocalBlock func(header *types.Header) bool, init bool) *multiWorker {
	queue := make(chan *task)

	greedyWorker := newWorker(config, chainConfig, engine, eth, mux, isLocalBlock, init, &flashbotsData{
		isFlashbots:      true,
		queue:            queue,
		algoType:         config.AlgoType,
		maxMergedBundles: config.MaxMergedBundles,
		bundleCache:      NewBundleCache(),
	})

	log.Info("creating new greedy worker")
	return &multiWorker{
		regularWorker: greedyWorker,
		workers:       []*worker{greedyWorker},
	}
}

// mev-geth deprecated
func newMultiWorkerMevGeth(config *Config, chainConfig *params.ChainConfig, engine consensus.Engine, eth Backend, mux *event.TypeMux, isLocalBlock func(header *types.Header) bool, init bool) *multiWorker {
	queue := make(chan *task)

	bundleCache := NewBundleCache()

	regularWorker := newWorker(config, chainConfig, engine, eth, mux, isLocalBlock, init, &flashbotsData{
		isFlashbots:      false,
		queue:            queue,
		algoType:         ALGO_MEV_GETH,
		maxMergedBundles: config.MaxMergedBundles,
		bundleCache:      bundleCache,
	})

	workers := []*worker{regularWorker}
	if config.AlgoType == ALGO_MEV_GETH {
		for i := 1; i <= config.MaxMergedBundles; i++ {
			workers = append(workers,
				newWorker(config, chainConfig, engine, eth, mux, isLocalBlock, init, &flashbotsData{
					isFlashbots:      true,
					queue:            queue,
					algoType:         ALGO_MEV_GETH,
					maxMergedBundles: i,
					bundleCache:      bundleCache,
				}))
		}
	}

	log.Info("creating multi worker", "config.MaxMergedBundles", config.MaxMergedBundles, "workers", len(workers))
	return &multiWorker{
		regularWorker: regularWorker,
		workers:       workers,
	}
}

type flashbotsData struct {
	isFlashbots      bool
	queue            chan *task
	maxMergedBundles int
	algoType         AlgoType
	bundleCache      *BundleCache
}
