package miner

import (
	"errors"
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

func (w *multiWorker) enablePreseal() {
	for _, worker := range w.workers {
		worker.enablePreseal()
	}
}

func (w *multiWorker) disablePreseal() {
	for _, worker := range w.workers {
		worker.disablePreseal()
	}
}

type resChPair struct {
	resCh chan *types.Block
	errCh chan error
}

func (w *multiWorker) buildPayload(args *BuildPayloadArgs) (*Payload, error) {
	// Build the initial version with no transaction included. It should be fast
	// enough to run. The empty payload can at least make sure there is something
	// to deliver for not missing slot.
	var empty *types.Block
	for _, worker := range w.workers {
		var err error
		empty, _, err = worker.getSealingBlock(args.Parent, args.Timestamp, args.FeeRecipient, args.GasLimit, args.Random, args.Withdrawals, true, nil)
		if err != nil {
			log.Error("could not start async block construction", "isFlashbotsWorker", worker.flashbots.isFlashbots, "#bundles", worker.flashbots.maxMergedBundles)
			continue
		}
		break
	}

	if empty == nil {
		return nil, errors.New("no worker could build an empty block")
	}

	// Construct a payload object for return.
	payload := newPayload(empty, args.Id())

	if len(w.workers) == 0 {
		return payload, nil
	}

	// Keep separate payloads for each worker so that ResolveFull actually resolves the best of all workers
	workerPayloads := []*Payload{}

	for _, w := range w.workers {
		workerPayload := newPayload(empty, args.Id())
		workerPayloads = append(workerPayloads, workerPayload)

		go func(w *worker) {
			// Update routine done elsewhere!
			start := time.Now()
			block, fees, err := w.getSealingBlock(args.Parent, args.Timestamp, args.FeeRecipient, args.GasLimit, args.Random, args.Withdrawals, false, args.BlockHook)
			if err == nil {
				workerPayload.update(block, fees, time.Since(start))
			}
		}(w)
	}

	go payload.resolveBestFullPayload(workerPayloads)

	return payload, nil
}

func newMultiWorker(config *Config, chainConfig *params.ChainConfig, engine consensus.Engine, eth Backend, mux *event.TypeMux, isLocalBlock func(header *types.Header) bool, init bool) *multiWorker {
	if config.AlgoType != ALGO_MEV_GETH {
		return newMultiWorkerGreedy(config, chainConfig, engine, eth, mux, isLocalBlock, init)
	} else {
		return newMultiWorkerMevGeth(config, chainConfig, engine, eth, mux, isLocalBlock, init)
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
