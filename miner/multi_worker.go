package miner

import (
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

func (w *multiWorker) GetSealingBlock(args *BuildPayloadArgs, noTxs bool, blockHook BlockHookFn) (chan *types.Block, error) {
	resCh := make(chan *types.Block)

	for _, w := range w.workers {
		go func(worker *worker) {
			var res *types.Block
			newBlock, _, err := worker.getSealingBlock(args.Parent, args.Timestamp, args.FeeRecipient, args.GasLimit, args.Random, args.Withdrawals, noTxs, blockHook)
			if err != nil {
				log.Error("could not generate block", "err", err, "isFlashbotsWorker", worker.flashbots.isFlashbots, "#bundles", worker.flashbots.maxMergedBundles)
				return
			}
			if res == nil || (newBlock != nil && newBlock.Profit.Cmp(res.Profit) > 0) {
				res = newBlock
			}
			resCh <- res
		}(w)
	}

	return resCh, nil
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
