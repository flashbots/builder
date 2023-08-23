// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package miner

import (
	"errors"
	"fmt"
	"math/big"

	"sort"
	"sync"
	"sync/atomic"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/tracers/logger"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
)

const (
	// resultQueueSize is the size of channel listening to sealing result.
	resultQueueSize = 20

	// txChanSize is the size of channel listening to NewTxsEvent.
	// The number is referenced from the size of tx pool.
	txChanSize = 4096

	// chainHeadChanSize is the size of channel listening to ChainHeadEvent.
	chainHeadChanSize = 10

	// chainSideChanSize is the size of channel listening to ChainSideEvent.
	chainSideChanSize = 10

	// resubmitAdjustChanSize is the size of resubmitting interval adjustment channel.
	resubmitAdjustChanSize = 10

	// sealingLogAtDepth is the number of confirmations before logging successful sealing.
	sealingLogAtDepth = 7

	// minRecommitInterval is the minimal time interval to recreate the sealing block with
	// any newly arrived transactions.
	minRecommitInterval = 1 * time.Second

	// maxRecommitInterval is the maximum time interval to recreate the sealing block with
	// any newly arrived transactions.
	maxRecommitInterval = 15 * time.Second

	// intervalAdjustRatio is the impact a single interval adjustment has on sealing work
	// resubmitting interval.
	intervalAdjustRatio = 0.1

	// intervalAdjustBias is applied during the new resubmit interval calculation in favor of
	// increasing upper limit or decreasing lower limit so that the limit can be reachable.
	intervalAdjustBias = 200 * 1000.0 * 1000.0

	// staleThreshold is the maximum depth of the acceptable stale block.
	staleThreshold = 7
)

var (
	errCouldNotApplyTransaction   = errors.New("could not apply transaction")
	errBlockInterruptedByNewHead  = errors.New("new head arrived while building block")
	errBlockInterruptedByRecommit = errors.New("recommit interrupt while building block")
	errBlocklistViolation         = errors.New("blocklist violation")
	errBlockInterruptedByTimeout  = errors.New("timeout while building block")
)

// environment is the worker's current environment and holds all
// information of the sealing block generation.
type environment struct {
	signer types.Signer

	state     *state.StateDB          // apply state changes here
	ancestors mapset.Set[common.Hash] // ancestor set (used for checking uncle parent validity)
	family    mapset.Set[common.Hash] // family set (used for checking uncle invalidity)
	tcount    int                     // tx count in cycle
	gasPool   *core.GasPool           // available gas used to pack transactions
	coinbase  common.Address
	profit    *big.Int

	header   *types.Header
	txs      []*types.Transaction
	receipts []*types.Receipt
	uncles   map[common.Hash]*types.Header
}

// copy creates a deep copy of environment.
func (env *environment) copy() *environment {
	cpy := &environment{
		signer:    env.signer,
		state:     env.state.Copy(),
		ancestors: env.ancestors.Clone(),
		family:    env.family.Clone(),
		tcount:    env.tcount,
		coinbase:  env.coinbase,
		profit:    new(big.Int).Set(env.profit),
		header:    types.CopyHeader(env.header),
		receipts:  copyReceipts(env.receipts),
	}
	if env.gasPool != nil {
		gasPool := *env.gasPool
		cpy.gasPool = &gasPool
	}
	// The content of txs and uncles are immutable, unnecessary
	// to do the expensive deep copy for them.
	cpy.txs = make([]*types.Transaction, len(env.txs))
	copy(cpy.txs, env.txs)
	cpy.uncles = make(map[common.Hash]*types.Header)
	for hash, uncle := range env.uncles {
		cpy.uncles[hash] = uncle
	}
	return cpy
}

// unclelist returns the contained uncles as the list format.
func (env *environment) unclelist() []*types.Header {
	var uncles []*types.Header
	for _, uncle := range env.uncles {
		uncles = append(uncles, uncle)
	}
	return uncles
}

// discard terminates the background prefetcher go-routine. It should
// always be called for all created environment instances otherwise
// the go-routine leak can happen.
func (env *environment) discard() {
	if env.state == nil {
		return
	}
	env.state.StopPrefetcher()
}

// task contains all information for consensus engine sealing and result submitting.
type task struct {
	receipts  []*types.Receipt
	state     *state.StateDB
	block     *types.Block
	createdAt time.Time

	profit      *big.Int
	isFlashbots bool
	worker      int
}

const (
	commitInterruptNone int32 = iota
	commitInterruptNewHead
	commitInterruptResubmit
	commitInterruptTimeout
)

// newWorkReq represents a request for new sealing work submitting with relative interrupt notifier.
type newWorkReq struct {
	interrupt *int32
	noempty   bool
	timestamp int64
}

// newPayloadResult represents a result struct corresponds to payload generation.
type newPayloadResult struct {
	err   error
	block *types.Block
	fees  *big.Int
}

// getWorkReq represents a request for getting a new sealing work with provided parameters.
type getWorkReq struct {
	params *generateParams
	result chan *newPayloadResult // non-blocking channel
}

// intervalAdjust represents a resubmitting interval adjustment.
type intervalAdjust struct {
	ratio float64
	inc   bool
}

// worker is the main object which takes care of submitting new work to consensus engine
// and gathering the sealing result.
type worker struct {
	config      *Config
	chainConfig *params.ChainConfig
	engine      consensus.Engine
	eth         Backend
	chain       *core.BlockChain
	blockList   map[common.Address]struct{}

	// Feeds
	pendingLogsFeed event.Feed

	// Subscriptions
	mux          *event.TypeMux
	txsCh        chan core.NewTxsEvent
	txsSub       event.Subscription
	chainHeadCh  chan core.ChainHeadEvent
	chainHeadSub event.Subscription
	chainSideCh  chan core.ChainSideEvent
	chainSideSub event.Subscription

	// Channels
	newWorkCh          chan *newWorkReq
	getWorkCh          chan *getWorkReq
	taskCh             chan *task
	resultCh           chan *types.Block
	startCh            chan struct{}
	exitCh             chan struct{}
	resubmitIntervalCh chan time.Duration
	resubmitAdjustCh   chan *intervalAdjust

	wg sync.WaitGroup

	current      *environment                 // An environment for current running cycle.
	localUncles  map[common.Hash]*types.Block // A set of side blocks generated locally as the possible uncle blocks.
	remoteUncles map[common.Hash]*types.Block // A set of side blocks as the possible uncle blocks.
	unconfirmed  *unconfirmedBlocks           // A set of locally mined blocks pending canonicalness confirmations.

	mu       sync.RWMutex // The lock used to protect the coinbase and extra fields
	coinbase common.Address
	extra    []byte

	pendingMu    sync.RWMutex
	pendingTasks map[common.Hash]*task

	snapshotMu       sync.RWMutex // The lock used to protect the snapshots below
	snapshotBlock    *types.Block
	snapshotReceipts types.Receipts
	snapshotState    *state.StateDB

	// atomic status counters
	running int32 // The indicator whether the consensus engine is running or not.
	newTxs  int32 // New arrival transaction count since last sealing work submitting.

	// noempty is the flag used to control whether the feature of pre-seal empty
	// block is enabled. The default value is false(pre-seal is enabled by default).
	// But in some special scenario the consensus engine will seal blocks instantaneously,
	// in this case this feature will add all empty blocks into canonical chain
	// non-stop and no real transaction will be included.
	noempty uint32

	// newpayloadTimeout is the maximum timeout allowance for creating payload.
	// The default value is 2 seconds but node operator can set it to arbitrary
	// large value. A large timeout allowance may cause Geth to fail creating
	// a non-empty payload within the specified time and eventually miss the slot
	// in case there are some computation expensive transactions in txpool.
	newpayloadTimeout time.Duration

	// recommit is the time interval to re-create sealing work or to re-build
	// payload in proof-of-stake stage.
	recommit time.Duration

	// External functions
	isLocalBlock func(header *types.Header) bool // Function used to determine whether the specified block is mined by local miner.

	flashbots *flashbotsData

	// Test hooks
	newTaskHook  func(*task)                        // Method to call upon receiving a new sealing task.
	skipSealHook func(*task) bool                   // Method to decide whether skipping the sealing.
	fullTaskHook func()                             // Method to call before pushing the full sealing task.
	resubmitHook func(time.Duration, time.Duration) // Method to call upon updating resubmitting interval.
}

func newWorker(config *Config, chainConfig *params.ChainConfig, engine consensus.Engine, eth Backend, mux *event.TypeMux, isLocalBlock func(header *types.Header) bool, init bool, flashbots *flashbotsData) *worker {
	var builderCoinbase common.Address
	if config.BuilderTxSigningKey == nil {
		log.Error("Builder tx signing key is not set")
		builderCoinbase = config.Etherbase
	} else {
		builderCoinbase = crypto.PubkeyToAddress(config.BuilderTxSigningKey.PublicKey)
	}

	log.Info("new worker", "builderCoinbase", builderCoinbase.String())
	exitCh := make(chan struct{})
	taskCh := make(chan *task)
	if flashbots.algoType == ALGO_MEV_GETH {
		if flashbots.isFlashbots {
			// publish to the flashbots queue
			taskCh = flashbots.queue
		} else {
			// read from the flashbots queue
			go func() {
				for {
					select {
					case flashbotsTask := <-flashbots.queue:
						select {
						case taskCh <- flashbotsTask:
						case <-exitCh:
							return
						}
					case <-exitCh:
						return
					}
				}
			}()
		}
	}

	blockList := make(map[common.Address]struct{})
	for _, address := range config.Blocklist {
		blockList[address] = struct{}{}
	}

	worker := &worker{
		config:             config,
		chainConfig:        chainConfig,
		engine:             engine,
		eth:                eth,
		chain:              eth.BlockChain(),
		blockList:          blockList,
		mux:                mux,
		isLocalBlock:       isLocalBlock,
		localUncles:        make(map[common.Hash]*types.Block),
		remoteUncles:       make(map[common.Hash]*types.Block),
		unconfirmed:        newUnconfirmedBlocks(eth.BlockChain(), sealingLogAtDepth),
		extra:              config.ExtraData,
		pendingTasks:       make(map[common.Hash]*task),
		txsCh:              make(chan core.NewTxsEvent, txChanSize),
		chainHeadCh:        make(chan core.ChainHeadEvent, chainHeadChanSize),
		chainSideCh:        make(chan core.ChainSideEvent, chainSideChanSize),
		newWorkCh:          make(chan *newWorkReq, 1),
		getWorkCh:          make(chan *getWorkReq),
		taskCh:             taskCh,
		resultCh:           make(chan *types.Block, resultQueueSize),
		startCh:            make(chan struct{}, 1),
		exitCh:             exitCh,
		resubmitIntervalCh: make(chan time.Duration),
		resubmitAdjustCh:   make(chan *intervalAdjust, resubmitAdjustChanSize),
		coinbase:           builderCoinbase,
		flashbots:          flashbots,
	}

	// Subscribe NewTxsEvent for tx pool
	worker.txsSub = eth.TxPool().SubscribeNewTxsEvent(worker.txsCh)
	// Subscribe events for blockchain
	worker.chainHeadSub = eth.BlockChain().SubscribeChainHeadEvent(worker.chainHeadCh)
	worker.chainSideSub = eth.BlockChain().SubscribeChainSideEvent(worker.chainSideCh)

	// Sanitize recommit interval if the user-specified one is too short.
	recommit := worker.config.Recommit
	if recommit < minRecommitInterval {
		log.Warn("Sanitizing miner recommit interval", "provided", recommit, "updated", minRecommitInterval)
		recommit = minRecommitInterval
	}
	worker.recommit = recommit

	// Sanitize the timeout config for creating payload.
	newpayloadTimeout := worker.config.NewPayloadTimeout
	if newpayloadTimeout == 0 {
		log.Warn("Sanitizing new payload timeout to default", "provided", newpayloadTimeout, "updated", DefaultConfig.NewPayloadTimeout)
		newpayloadTimeout = DefaultConfig.NewPayloadTimeout
	}
	if newpayloadTimeout < time.Millisecond*100 {
		log.Warn("Low payload timeout may cause high amount of non-full blocks", "provided", newpayloadTimeout, "default", DefaultConfig.NewPayloadTimeout)
	}
	worker.newpayloadTimeout = newpayloadTimeout

	worker.wg.Add(2)
	go worker.mainLoop()
	go worker.newWorkLoop(recommit)
	if flashbots.algoType != ALGO_MEV_GETH || !flashbots.isFlashbots {
		// only mine if not flashbots
		worker.wg.Add(2)
		go worker.resultLoop()
		go worker.taskLoop()
	}

	// Submit first work to initialize pending state.
	if init {
		worker.startCh <- struct{}{}
	}
	return worker
}

// setEtherbase sets the etherbase used to initialize the block coinbase field.
func (w *worker) setEtherbase(addr common.Address) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.coinbase = addr
}

// etherbase retrieves the configured etherbase address.
func (w *worker) etherbase() common.Address {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.coinbase
}

func (w *worker) setGasCeil(ceil uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.config.GasCeil = ceil
}

// setExtra sets the content used to initialize the block extra field.
func (w *worker) setExtra(extra []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.extra = extra
}

// setRecommitInterval updates the interval for miner sealing work recommitting.
func (w *worker) setRecommitInterval(interval time.Duration) {
	select {
	case w.resubmitIntervalCh <- interval:
	case <-w.exitCh:
	}
}

// disablePreseal disables pre-sealing feature
func (w *worker) disablePreseal() {
	atomic.StoreUint32(&w.noempty, 1)
}

// enablePreseal enables pre-sealing feature
func (w *worker) enablePreseal() {
	atomic.StoreUint32(&w.noempty, 0)
}

// pending returns the pending state and corresponding block.
func (w *worker) pending() (*types.Block, *state.StateDB) {
	// return a snapshot to avoid contention on currentMu mutex
	w.snapshotMu.RLock()
	defer w.snapshotMu.RUnlock()
	if w.snapshotState == nil {
		return nil, nil
	}
	return w.snapshotBlock, w.snapshotState.Copy()
}

// pendingBlock returns pending block.
func (w *worker) pendingBlock() *types.Block {
	// return a snapshot to avoid contention on currentMu mutex
	w.snapshotMu.RLock()
	defer w.snapshotMu.RUnlock()
	return w.snapshotBlock
}

// pendingBlockAndReceipts returns pending block and corresponding receipts.
func (w *worker) pendingBlockAndReceipts() (*types.Block, types.Receipts) {
	// return a snapshot to avoid contention on currentMu mutex
	w.snapshotMu.RLock()
	defer w.snapshotMu.RUnlock()
	return w.snapshotBlock, w.snapshotReceipts
}

// start sets the running status as 1 and triggers new work submitting.
func (w *worker) start() {
	atomic.StoreInt32(&w.running, 1)
	w.startCh <- struct{}{}
}

// stop sets the running status as 0.
func (w *worker) stop() {
	atomic.StoreInt32(&w.running, 0)
}

// isRunning returns an indicator whether worker is running or not.
func (w *worker) isRunning() bool {
	return atomic.LoadInt32(&w.running) == 1
}

// close terminates all background threads maintained by the worker.
// Note the worker does not support being closed multiple times.
func (w *worker) close() {
	atomic.StoreInt32(&w.running, 0)
	close(w.exitCh)
	w.wg.Wait()
}

// recalcRecommit recalculates the resubmitting interval upon feedback.
func recalcRecommit(minRecommit, prev time.Duration, target float64, inc bool) time.Duration {
	var (
		prevF = float64(prev.Nanoseconds())
		next  float64
	)
	if inc {
		next = prevF*(1-intervalAdjustRatio) + intervalAdjustRatio*(target+intervalAdjustBias)
		max := float64(maxRecommitInterval.Nanoseconds())
		if next > max {
			next = max
		}
	} else {
		next = prevF*(1-intervalAdjustRatio) + intervalAdjustRatio*(target-intervalAdjustBias)
		min := float64(minRecommit.Nanoseconds())
		if next < min {
			next = min
		}
	}
	return time.Duration(int64(next))
}

// newWorkLoop is a standalone goroutine to submit new sealing work upon received events.
func (w *worker) newWorkLoop(recommit time.Duration) {
	defer w.wg.Done()
	var (
		runningInterrupt *int32     // Running task interrupt
		queuedInterrupt  *int32     // Queued task interrupt
		minRecommit      = recommit // minimal resubmit interval specified by user.
		timestamp        int64      // timestamp for each round of sealing.
	)

	timer := time.NewTimer(0)
	defer timer.Stop()
	<-timer.C // discard the initial tick

	// commit aborts in-flight transaction execution with highest seen signal and resubmits a new one
	commit := func(noempty bool, s int32) {
		select {
		case <-w.exitCh:
			return
		case queuedRequest := <-w.newWorkCh:
			// Previously queued request wasn't started yet, update the request and resubmit
			queuedRequest.noempty = queuedRequest.noempty || noempty
			queuedRequest.timestamp = timestamp
			w.newWorkCh <- queuedRequest // guaranteed to be nonblocking
		default:
			// Previously queued request has already started, cycle interrupt pointer and submit new work
			runningInterrupt = queuedInterrupt
			queuedInterrupt = new(int32)

			w.newWorkCh <- &newWorkReq{interrupt: queuedInterrupt, noempty: noempty, timestamp: timestamp} // guaranteed to be nonblocking
		}

		if runningInterrupt != nil && s > atomic.LoadInt32(runningInterrupt) {
			atomic.StoreInt32(runningInterrupt, s)
		}

		timer.Reset(recommit)
		atomic.StoreInt32(&w.newTxs, 0)
	}
	// clearPending cleans the stale pending tasks.
	clearPending := func(number uint64) {
		w.pendingMu.Lock()
		for h, t := range w.pendingTasks {
			if t.block.NumberU64()+staleThreshold <= number {
				delete(w.pendingTasks, h)
			}
		}
		w.pendingMu.Unlock()
	}

	for {
		select {
		case <-w.startCh:
			clearPending(w.chain.CurrentBlock().Number.Uint64())
			timestamp = time.Now().Unix()
			commit(false, commitInterruptNewHead)

		case head := <-w.chainHeadCh:
			clearPending(head.Block.NumberU64())
			timestamp = time.Now().Unix()
			commit(false, commitInterruptNewHead)

		case <-timer.C:
			// If sealing is running resubmit a new work cycle periodically to pull in
			// higher priced transactions. Disable this overhead for pending blocks.
			if w.isRunning() && (w.chainConfig.Clique == nil || w.chainConfig.Clique.Period > 0) {
				// flashbots: disable this because there can be new bundles
				// Short circuit if no new transaction arrives.
				//if atomic.LoadInt32(&w.newTxs) == 0 {
				//	timer.Reset(recommit)
				//	continue
				//}
				commit(true, commitInterruptResubmit)
			}

		case interval := <-w.resubmitIntervalCh:
			// Adjust resubmit interval explicitly by user.
			if interval < minRecommitInterval {
				log.Warn("Sanitizing miner recommit interval", "provided", interval, "updated", minRecommitInterval)
				interval = minRecommitInterval
			}
			log.Info("Miner recommit interval update", "from", minRecommit, "to", interval)
			minRecommit, recommit = interval, interval

			if w.resubmitHook != nil {
				w.resubmitHook(minRecommit, recommit)
			}

		case adjust := <-w.resubmitAdjustCh:
			// Adjust resubmit interval by feedback.
			if adjust.inc {
				before := recommit
				target := float64(recommit.Nanoseconds()) / adjust.ratio
				recommit = recalcRecommit(minRecommit, recommit, target, true)
				log.Trace("Increase miner recommit interval", "from", before, "to", recommit)
			} else {
				before := recommit
				recommit = recalcRecommit(minRecommit, recommit, float64(minRecommit.Nanoseconds()), false)
				log.Trace("Decrease miner recommit interval", "from", before, "to", recommit)
			}

			if w.resubmitHook != nil {
				w.resubmitHook(minRecommit, recommit)
			}

		case <-w.exitCh:
			return
		}
	}
}

// mainLoop is responsible for generating and submitting sealing work based on
// the received event. It can support two modes: automatically generate task and
// submit it or return task according to given parameters for various proposes.
func (w *worker) mainLoop() {
	defer w.wg.Done()
	defer w.txsSub.Unsubscribe()
	defer w.chainHeadSub.Unsubscribe()
	defer w.chainSideSub.Unsubscribe()
	defer func() {
		if w.current != nil {
			w.current.discard()
		}
	}()

	cleanTicker := time.NewTicker(time.Second * 10)
	defer cleanTicker.Stop()

	for {
		select {
		case req := <-w.newWorkCh:
			// Don't start if the work has already been interrupted
			if req.interrupt == nil || atomic.LoadInt32(req.interrupt) == commitInterruptNone {
				w.commitWork(req.interrupt, req.noempty, req.timestamp)
			}

		case req := <-w.getWorkCh:
			go func() {
				block, fees, err := w.generateWork(req.params)
				req.result <- &newPayloadResult{
					err:   err,
					block: block,
					fees:  fees,
				}
			}()
		case ev := <-w.chainSideCh:
			// Short circuit for duplicate side blocks
			if _, exist := w.localUncles[ev.Block.Hash()]; exist {
				continue
			}
			if _, exist := w.remoteUncles[ev.Block.Hash()]; exist {
				continue
			}
			// Add side block to possible uncle block set depending on the author.
			if w.isLocalBlock != nil && w.isLocalBlock(ev.Block.Header()) {
				w.localUncles[ev.Block.Hash()] = ev.Block
			} else {
				w.remoteUncles[ev.Block.Hash()] = ev.Block
			}
			// If our sealing block contains less than 2 uncle blocks,
			// add the new uncle block if valid and regenerate a new
			// sealing block for higher profit.
			if w.isRunning() && w.current != nil && len(w.current.uncles) < 2 {
				start := time.Now()
				if err := w.commitUncle(w.current, ev.Block.Header()); err == nil {
					w.commit(w.current.copy(), nil, true, start)
				}
			}

		case <-cleanTicker.C:
			chainHead := w.chain.CurrentBlock()
			for hash, uncle := range w.localUncles {
				if uncle.NumberU64()+staleThreshold <= chainHead.Number.Uint64() {
					delete(w.localUncles, hash)
				}
			}
			for hash, uncle := range w.remoteUncles {
				if uncle.NumberU64()+staleThreshold <= chainHead.Number.Uint64() {
					delete(w.remoteUncles, hash)
				}
			}

		case ev := <-w.txsCh:
			// Apply transactions to the pending state if we're not sealing
			//
			// Note all transactions received may not be continuous with transactions
			// already included in the current sealing block. These transactions will
			// be automatically eliminated.
			if !w.isRunning() && w.current != nil {
				// If block is already full, abort
				if gp := w.current.gasPool; gp != nil && gp.Gas() < params.TxGas {
					continue
				}
				txs := make(map[common.Address]types.Transactions)
				for _, tx := range ev.Txs {
					acc, _ := types.Sender(w.current.signer, tx)
					txs[acc] = append(txs[acc], tx)
				}
				txset := types.NewTransactionsByPriceAndNonce(w.current.signer, txs, nil, nil, w.current.header.BaseFee)
				tcount := w.current.tcount
				w.commitTransactions(w.current, txset, nil)

				// Only update the snapshot if any new transactions were added
				// to the pending block
				if tcount != w.current.tcount {
					w.updateSnapshot(w.current)
				}
			} else {
				// Special case, if the consensus engine is 0 period clique(dev mode),
				// submit sealing work here since all empty submission will be rejected
				// by clique. Of course the advance sealing(empty submission) is disabled.
				if w.chainConfig.Clique != nil && w.chainConfig.Clique.Period == 0 {
					w.commitWork(nil, true, time.Now().Unix())
				}
			}
			atomic.AddInt32(&w.newTxs, int32(len(ev.Txs)))

		// System stopped
		case <-w.exitCh:
			return
		case <-w.txsSub.Err():
			return
		case <-w.chainHeadSub.Err():
			return
		case <-w.chainSideSub.Err():
			return
		}
	}
}

// taskLoop is a standalone goroutine to fetch sealing task from the generator and
// push them to consensus engine.
func (w *worker) taskLoop() {
	defer w.wg.Done()
	var (
		stopCh chan struct{}
		prev   common.Hash

		prevParentHash common.Hash
		prevProfit     *big.Int
	)

	// interrupt aborts the in-flight sealing task.
	interrupt := func() {
		if stopCh != nil {
			close(stopCh)
			stopCh = nil
		}
	}
	for {
		select {
		case task := <-w.taskCh:
			if w.newTaskHook != nil {
				w.newTaskHook(task)
			}
			// Reject duplicate sealing work due to resubmitting.
			sealHash := w.engine.SealHash(task.block.Header())
			if sealHash == prev {
				continue
			}

			taskParentHash := task.block.Header().ParentHash
			// reject new tasks which don't profit
			if taskParentHash == prevParentHash &&
				prevProfit != nil && task.profit.Cmp(prevProfit) < 0 {
				continue
			}
			prevParentHash = taskParentHash
			prevProfit = task.profit

			// Interrupt previous sealing operation
			interrupt()
			stopCh, prev = make(chan struct{}), sealHash
			log.Info("Proposed miner block", "blockNumber", task.block.Number(), "profit", ethIntToFloat(prevProfit), "isFlashbots", task.isFlashbots, "sealhash", sealHash, "parentHash", prevParentHash, "worker", task.worker)
			if w.skipSealHook != nil && w.skipSealHook(task) {
				continue
			}
			w.pendingMu.Lock()
			w.pendingTasks[sealHash] = task
			w.pendingMu.Unlock()

			if err := w.engine.Seal(w.chain, task.block, task.profit, w.resultCh, stopCh); err != nil {
				log.Warn("Block sealing failed", "err", err)
				w.pendingMu.Lock()
				delete(w.pendingTasks, sealHash)
				w.pendingMu.Unlock()
			}
		case <-w.exitCh:
			interrupt()
			return
		}
	}
}

// resultLoop is a standalone goroutine to handle sealing result submitting
// and flush relative data to the database.
func (w *worker) resultLoop() {
	defer w.wg.Done()
	for {
		select {
		case block := <-w.resultCh:
			// Short circuit when receiving empty result.
			if block == nil {
				continue
			}
			// Short circuit when receiving duplicate result caused by resubmitting.
			if w.chain.HasBlock(block.Hash(), block.NumberU64()) {
				continue
			}
			var (
				sealhash = w.engine.SealHash(block.Header())
				hash     = block.Hash()
			)
			w.pendingMu.RLock()
			task, exist := w.pendingTasks[sealhash]
			w.pendingMu.RUnlock()
			if !exist {
				log.Error("Block found but no relative pending task", "number", block.Number(), "sealhash", sealhash, "hash", hash)
				continue
			}
			// Different block could share same sealhash, deep copy here to prevent write-write conflict.
			var (
				receipts = make([]*types.Receipt, len(task.receipts))
				logs     []*types.Log
			)
			for i, taskReceipt := range task.receipts {
				receipt := new(types.Receipt)
				receipts[i] = receipt
				*receipt = *taskReceipt

				// add block location fields
				receipt.BlockHash = hash
				receipt.BlockNumber = block.Number()
				receipt.TransactionIndex = uint(i)

				// Update the block hash in all logs since it is now available and not when the
				// receipt/log of individual transactions were created.
				receipt.Logs = make([]*types.Log, len(taskReceipt.Logs))
				for i, taskLog := range taskReceipt.Logs {
					log := new(types.Log)
					receipt.Logs[i] = log
					*log = *taskLog
					log.BlockHash = hash
				}
				logs = append(logs, receipt.Logs...)
			}
			// Commit block and state to database.
			_, err := w.chain.WriteBlockAndSetHead(block, receipts, logs, task.state, true)
			if err != nil {
				log.Error("Failed writing block to chain", "err", err)
				continue
			}
			log.Info("Successfully sealed new block", "number", block.Number(), "sealhash", sealhash, "hash", hash,
				"elapsed", common.PrettyDuration(time.Since(task.createdAt)))

			// Broadcast the block and announce chain insertion event
			w.mux.Post(core.NewMinedBlockEvent{Block: block})

			// Insert the block into the set of pending ones to resultLoop for confirmations
			w.unconfirmed.Insert(block.NumberU64(), block.Hash())

		case <-w.exitCh:
			return
		}
	}
}

// makeEnv creates a new environment for the sealing block.
func (w *worker) makeEnv(parent *types.Header, header *types.Header, coinbase common.Address) (*environment, error) {
	// Retrieve the parent state to execute on top and start a prefetcher for
	// the miner to speed block sealing up a bit.
	state, err := w.chain.StateAt(parent.Root)
	if err != nil {
		return nil, err
	}
	state.StartPrefetcher("miner")

	// Note the passed coinbase may be different with header.Coinbase.
	env := &environment{
		signer:    types.MakeSigner(w.chainConfig, header.Number),
		state:     state,
		coinbase:  coinbase,
		ancestors: mapset.NewSet[common.Hash](),
		family:    mapset.NewSet[common.Hash](),
		header:    header,
		uncles:    make(map[common.Hash]*types.Header),
		profit:    new(big.Int),
	}
	// when 08 is processed ancestors contain 07 (quick block)
	for _, ancestor := range w.chain.GetBlocksFromHash(parent.Hash(), 7) {
		for _, uncle := range ancestor.Uncles() {
			env.family.Add(uncle.Hash())
		}
		env.family.Add(ancestor.Hash())
		env.ancestors.Add(ancestor.Hash())
	}
	// Keep track of transactions which return errors so they can be removed
	env.tcount = 0
	env.gasPool = new(core.GasPool).AddGas(header.GasLimit)
	return env, nil
}

// commitUncle adds the given block to uncle block set, returns error if failed to add.
func (w *worker) commitUncle(env *environment, uncle *types.Header) error {
	if w.isTTDReached(env.header) {
		return errors.New("ignore uncle for beacon block")
	}
	hash := uncle.Hash()
	if _, exist := env.uncles[hash]; exist {
		return errors.New("uncle not unique")
	}
	if env.header.ParentHash == uncle.ParentHash {
		return errors.New("uncle is sibling")
	}
	if !env.ancestors.Contains(uncle.ParentHash) {
		return errors.New("uncle's parent unknown")
	}
	if env.family.Contains(hash) {
		return errors.New("uncle already included")
	}
	env.uncles[hash] = uncle
	return nil
}

// updateSnapshot updates pending snapshot block, receipts and state.
func (w *worker) updateSnapshot(env *environment) {
	w.snapshotMu.Lock()
	defer w.snapshotMu.Unlock()

	w.snapshotBlock = types.NewBlock(
		env.header,
		env.txs,
		env.unclelist(),
		env.receipts,
		trie.NewStackTrie(nil),
	)
	w.snapshotReceipts = copyReceipts(env.receipts)
	w.snapshotState = env.state.Copy()
}

func (w *worker) commitTransaction(env *environment, tx *types.Transaction) ([]*types.Log, error) {
	gasPool := *env.gasPool
	envGasUsed := env.header.GasUsed
	stateDB := env.state

	// It's important to copy then .SetTxContext() - don't reorder.
	stateDB.SetTxContext(tx.Hash(), env.tcount)

	snapshot := stateDB.Snapshot()

	gasPrice, err := tx.EffectiveGasTip(env.header.BaseFee)
	if err != nil {
		return nil, err
	}

	var tracer *logger.AccountTouchTracer
	var hook func() error
	config := *w.chain.GetVMConfig()
	if len(w.blockList) != 0 {
		tracer = logger.NewAccountTouchTracer()
		config.Tracer = tracer
		config.Debug = true
		hook = func() error {
			for _, address := range tracer.TouchedAddresses() {
				if _, in := w.blockList[address]; in {
					return errBlocklistViolation
				}
			}
			return nil
		}
	}

	receipt, err := core.ApplyTransaction(w.chainConfig, w.chain, &env.coinbase, &gasPool, stateDB, env.header, tx, &envGasUsed, config, hook)
	if err != nil {
		stateDB.RevertToSnapshot(snapshot)
		return nil, err
	}

	*env.gasPool = gasPool
	env.header.GasUsed = envGasUsed
	env.state = stateDB

	env.txs = append(env.txs, tx)
	env.receipts = append(env.receipts, receipt)

	gasUsed := new(big.Int).SetUint64(receipt.GasUsed)
	env.profit.Add(env.profit, gasUsed.Mul(gasUsed, gasPrice))

	return receipt.Logs, nil
}

func (w *worker) commitBundle(env *environment, txs types.Transactions, interrupt *int32) error {
	gasLimit := env.header.GasLimit
	if env.gasPool == nil {
		env.gasPool = new(core.GasPool).AddGas(gasLimit)
	}

	var coalescedLogs []*types.Log

	for _, tx := range txs {
		// Check interruption signal and abort building if it's fired.
		if interrupt != nil {
			if signal := atomic.LoadInt32(interrupt); signal != commitInterruptNone {
				return signalToErr(signal)
			}
		}
		// If we don't have enough gas for any further transactions discard the block
		// since not all bundles of the were applied
		if env.gasPool.Gas() < params.TxGas {
			log.Trace("Not enough gas for further transactions", "have", env.gasPool, "want", params.TxGas)
			return errCouldNotApplyTransaction
		}

		// Error may be ignored here. The error has already been checked
		// during transaction acceptance is the transaction pool.
		//
		// We use the eip155 signer regardless of the current hf.
		from, _ := types.Sender(env.signer, tx)
		// Check whether the tx is replay protected. If we're not in the EIP155 hf
		// phase, start ignoring the sender until we do.
		if tx.Protected() && !w.chainConfig.IsEIP155(env.header.Number) {
			log.Trace("Ignoring reply protected transaction", "hash", tx.Hash(), "eip155", w.chainConfig.EIP155Block)
			return errCouldNotApplyTransaction
		}

		logs, err := w.commitTransaction(env, tx)
		switch {
		case errors.Is(err, core.ErrGasLimitReached):
			// Pop the current out-of-gas transaction without shifting in the next from the account
			log.Trace("Gas limit exceeded for current block", "sender", from)
			return errCouldNotApplyTransaction

		case errors.Is(err, core.ErrNonceTooLow):
			// New head notification data race between the transaction pool and miner, shift
			log.Trace("Skipping transaction with low nonce", "sender", from, "nonce", tx.Nonce())
			return errCouldNotApplyTransaction

		case errors.Is(err, core.ErrNonceTooHigh):
			// Reorg notification data race between the transaction pool and miner, skip account =
			log.Trace("Skipping account with hight nonce", "sender", from, "nonce", tx.Nonce())
			return errCouldNotApplyTransaction

		case errors.Is(err, nil):
			// Everything ok, collect the logs and shift in the next transaction from the same account
			coalescedLogs = append(coalescedLogs, logs...)
			env.tcount++
			continue

		case errors.Is(err, core.ErrTxTypeNotSupported):
			// Pop the unsupported transaction without shifting in the next from the account
			log.Trace("Skipping unsupported transaction type", "sender", from, "type", tx.Type())
			return errCouldNotApplyTransaction

		default:
			// Strange error, discard the transaction and get the next in line (note, the
			// nonce-too-high clause will prevent us from executing in vain).
			log.Debug("Transaction failed, account skipped", "hash", tx.Hash(), "err", err)
			return errCouldNotApplyTransaction
		}
	}

	if !w.isRunning() && len(coalescedLogs) > 0 {
		// We don't push the pendingLogsEvent while we are sealing. The reason is that
		// when we are sealing, the worker will regenerate a sealing block every 3 seconds.
		// In order to avoid pushing the repeated pendingLog, we disable the pending log pushing.

		// make a copy, the state caches the logs and these logs get "upgraded" from pending to mined
		// logs by filling in the block hash when the block was mined by the local miner. This can
		// cause a race condition if a log was "upgraded" before the PendingLogsEvent is processed.
		cpy := make([]*types.Log, len(coalescedLogs))
		for i, l := range coalescedLogs {
			cpy[i] = new(types.Log)
			*cpy[i] = *l
		}
		w.pendingLogsFeed.Send(cpy)
	}

	return nil
}

func (w *worker) commitTransactions(env *environment, txs *types.TransactionsByPriceAndNonce, interrupt *int32) error {
	gasLimit := env.header.GasLimit
	if env.gasPool == nil {
		env.gasPool = new(core.GasPool).AddGas(gasLimit)
	}
	var coalescedLogs []*types.Log

	for {
		// Check interruption signal and abort building if it's fired.
		if interrupt != nil {
			if signal := atomic.LoadInt32(interrupt); signal != commitInterruptNone {
				return signalToErr(signal)
			}
		}
		// If we don't have enough gas for any further transactions then we're done.
		if env.gasPool.Gas() < params.TxGas {
			log.Trace("Not enough gas for further transactions", "have", env.gasPool, "want", params.TxGas)
			break
		}
		// Retrieve the next transaction and abort if all done
		order := txs.Peek()
		if order == nil {
			break
		}
		tx := order.Tx()
		if tx == nil {
			continue
		}
		// Error may be ignored here. The error has already been checked
		// during transaction acceptance is the transaction pool.
		from, _ := types.Sender(env.signer, tx)

		// Check whether the tx is replay protected. If we're not in the EIP155 hf
		// phase, start ignoring the sender until we do.
		if tx.Protected() && !w.chainConfig.IsEIP155(env.header.Number) {
			log.Trace("Ignoring reply protected transaction", "hash", tx.Hash(), "eip155", w.chainConfig.EIP155Block)

			txs.Pop()
			continue
		}

		logs, err := w.commitTransaction(env, tx)
		switch {
		case errors.Is(err, core.ErrGasLimitReached):
			// Pop the current out-of-gas transaction without shifting in the next from the account
			log.Trace("Gas limit exceeded for current block", "sender", from)
			txs.Pop()

		case errors.Is(err, core.ErrNonceTooLow):
			// New head notification data race between the transaction pool and miner, shift
			log.Trace("Skipping transaction with low nonce", "sender", from, "nonce", tx.Nonce())
			txs.Shift()

		case errors.Is(err, core.ErrNonceTooHigh):
			// Reorg notification data race between the transaction pool and miner, skip account =
			log.Trace("Skipping account with hight nonce", "sender", from, "nonce", tx.Nonce())
			txs.Pop()

		case errors.Is(err, nil):
			// Everything ok, collect the logs and shift in the next transaction from the same account
			coalescedLogs = append(coalescedLogs, logs...)
			env.tcount++
			txs.Shift()

		case errors.Is(err, types.ErrTxTypeNotSupported):
			// Pop the unsupported transaction without shifting in the next from the account
			log.Trace("Skipping unsupported transaction type", "sender", from, "type", tx.Type())
			txs.Pop()

		default:
			// Strange error, discard the transaction and get the next in line (note, the
			// nonce-too-high clause will prevent us from executing in vain).
			log.Debug("Transaction failed, account skipped", "hash", tx.Hash(), "err", err)
			txs.Shift()
		}
	}
	if !w.isRunning() && len(coalescedLogs) > 0 {
		// We don't push the pendingLogsEvent while we are sealing. The reason is that
		// when we are sealing, the worker will regenerate a sealing block every 3 seconds.
		// In order to avoid pushing the repeated pendingLog, we disable the pending log pushing.

		// make a copy, the state caches the logs and these logs get "upgraded" from pending to mined
		// logs by filling in the block hash when the block was mined by the local miner. This can
		// cause a race condition if a log was "upgraded" before the PendingLogsEvent is processed.
		cpy := make([]*types.Log, len(coalescedLogs))
		for i, l := range coalescedLogs {
			cpy[i] = new(types.Log)
			*cpy[i] = *l
		}
		w.pendingLogsFeed.Send(cpy)
	}
	return nil
}

// generateParams wraps various of settings for generating sealing task.
type generateParams struct {
	timestamp   uint64            // The timstamp for sealing task
	forceTime   bool              // Flag whether the given timestamp is immutable or not
	parentHash  common.Hash       // Parent block hash, empty means the latest chain head
	coinbase    common.Address    // The fee recipient address for including transaction
	gasLimit    uint64            // The validator's requested gas limit target
	random      common.Hash       // The randomness generated by beacon chain, empty before the merge
	withdrawals types.Withdrawals // List of withdrawals to include in block.
	noUncle     bool              // Flag whether the uncle block inclusion is allowed
	noTxs       bool              // Flag whether an empty block without any transaction is expected
	onBlock     BlockHookFn       // Callback to call for each produced block
}

func doPrepareHeader(genParams *generateParams, chain *core.BlockChain, config *Config, chainConfig *params.ChainConfig, extra []byte, engine consensus.Engine) (*types.Header, *types.Header, error) {
	// Find the parent block for sealing task
	parent := chain.CurrentBlock()
	if genParams.parentHash != (common.Hash{}) {
		block := chain.GetBlockByHash(genParams.parentHash)
		if block == nil {
			return nil, nil, fmt.Errorf("missing parent")
		}
		parent = block.Header()
	}

	// Sanity check the timestamp correctness, recap the timestamp
	// to parent+1 if the mutation is allowed.
	timestamp := genParams.timestamp
	if parent.Time >= timestamp {
		if genParams.forceTime {
			return nil, nil, fmt.Errorf("invalid timestamp, parent %d given %d", parent.Time, timestamp)
		}
		timestamp = parent.Time + 1
	}
	// Construct the sealing block header, set the extra field if it's allowed
	gasTarget := genParams.gasLimit
	if gasTarget == 0 {
		gasTarget = config.GasCeil
	}
	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     new(big.Int).Add(parent.Number, common.Big1),
		GasLimit:   core.CalcGasLimit(parent.GasLimit, gasTarget),
		Time:       timestamp,
		Coinbase:   genParams.coinbase,
	}
	if len(extra) != 0 {
		header.Extra = extra
	}

	// Set the randomness field from the beacon chain if it's available.
	if genParams.random != (common.Hash{}) {
		header.MixDigest = genParams.random
	}
	// Set baseFee and GasLimit if we are on an EIP-1559 chain
	if chainConfig.IsLondon(header.Number) {
		header.BaseFee = misc.CalcBaseFee(chainConfig, parent)
		if !chainConfig.IsLondon(parent.Number) {
			parentGasLimit := parent.GasLimit * chainConfig.ElasticityMultiplier()
			header.GasLimit = core.CalcGasLimit(parentGasLimit, gasTarget)
		}
	}
	// Run the consensus preparation with the default or customized consensus engine.
	if err := engine.Prepare(chain, header); err != nil {
		log.Error("Failed to prepare header for sealing", "err", err)
		return nil, nil, err
	}

	return header, parent, nil
}

// prepareWork constructs the sealing task according to the given parameters,
// either based on the last chain head or specified parent. In this function
// the pending transactions are not filled yet, only the empty task returned.
func (w *worker) prepareWork(genParams *generateParams) (*environment, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	header, parent, err := doPrepareHeader(genParams, w.chain, w.config, w.chainConfig, w.extra, w.engine)
	if err != nil {
		return nil, err
	}
	// uncomment to enable dirty fix for clique coinbase for local builder
	//header.Coinbase = genParams.coinbase

	// Could potentially happen if starting to mine in an odd state.
	// Note genParams.coinbase can be different with header.Coinbase
	// since clique algorithm can modify the coinbase field in header.
	env, err := w.makeEnv(parent, header, genParams.coinbase)
	if err != nil {
		log.Error("Failed to create sealing context", "err", err)
		return nil, err
	}
	// Accumulate the uncles for the sealing work only if it's allowed.
	if !genParams.noUncle {
		commitUncles := func(blocks map[common.Hash]*types.Block) {
			for hash, uncle := range blocks {
				if len(env.uncles) == 2 {
					break
				}
				if err := w.commitUncle(env, uncle.Header()); err != nil {
					log.Trace("Possible uncle rejected", "hash", hash, "reason", err)
				} else {
					log.Debug("Committing new uncle to block", "hash", hash)
				}
			}
		}
		// Prefer to locally generated uncle
		commitUncles(w.localUncles)
		commitUncles(w.remoteUncles)
	}
	return env, nil
}

func (w *worker) fillTransactionsSelectAlgo(interrupt *int32, env *environment) ([]types.SimulatedBundle, []types.SimulatedBundle, []types.UsedSBundle, map[common.Hash]struct{}, error) {
	var (
		blockBundles    []types.SimulatedBundle
		allBundles      []types.SimulatedBundle
		usedSbundles    []types.UsedSBundle
		mempoolTxHashes map[common.Hash]struct{}
		err             error
	)
	switch w.flashbots.algoType {
	case ALGO_GREEDY, ALGO_GREEDY_BUCKETS, ALGO_GREEDY_MULTISNAP, ALGO_GREEDY_BUCKETS_MULTISNAP:
		blockBundles, allBundles, usedSbundles, mempoolTxHashes, err = w.fillTransactionsAlgoWorker(interrupt, env)
	case ALGO_MEV_GETH:
		blockBundles, allBundles, mempoolTxHashes, err = w.fillTransactions(interrupt, env)
	default:
		blockBundles, allBundles, mempoolTxHashes, err = w.fillTransactions(interrupt, env)
	}
	return blockBundles, allBundles, usedSbundles, mempoolTxHashes, err
}

// fillTransactions retrieves the pending transactions from the txpool and fills them
// into the given sealing block. The transaction selection and ordering strategy can
// be customized with the plugin in the future.
// Returns error if any, otherwise the bundles that made it into the block and all bundles that passed simulation
func (w *worker) fillTransactions(interrupt *int32, env *environment) ([]types.SimulatedBundle, []types.SimulatedBundle, map[common.Hash]struct{}, error) {
	// Split the pending transactions into locals and remotes
	// Fill the block with all available pending transactions.
	pending := w.eth.TxPool().Pending(true)
	mempoolTxHashes := make(map[common.Hash]struct{}, len(pending))
	for _, txs := range pending {
		for _, tx := range txs {
			mempoolTxHashes[tx.Hash()] = struct{}{}
		}
	}
	localTxs, remoteTxs := make(map[common.Address]types.Transactions), pending
	for _, account := range w.eth.TxPool().Locals() {
		if txs := remoteTxs[account]; len(txs) > 0 {
			delete(remoteTxs, account)
			localTxs[account] = txs
		}
	}

	var blockBundles []types.SimulatedBundle
	var allBundles []types.SimulatedBundle
	if w.flashbots.isFlashbots {
		bundles, ccBundleCh := w.eth.TxPool().MevBundles(env.header.Number, env.header.Time)
		bundles = append(bundles, <-ccBundleCh...)

		var (
			bundleTxs       types.Transactions
			resultingBundle simulatedBundle
			mergedBundles   []types.SimulatedBundle
			numBundles      int
			err             error
		)
		// Sets allBundles in outer scope
		bundleTxs, resultingBundle, mergedBundles, numBundles, allBundles, err = w.generateFlashbotsBundle(env, bundles, pending)
		if err != nil {
			log.Error("Failed to generate flashbots bundle", "err", err)
			return nil, nil, nil, err
		}
		log.Info("Flashbots bundle", "ethToCoinbase", ethIntToFloat(resultingBundle.TotalEth), "gasUsed", resultingBundle.TotalGasUsed, "bundleScore", resultingBundle.MevGasPrice, "bundleLength", len(bundleTxs), "numBundles", numBundles, "worker", w.flashbots.maxMergedBundles)
		if len(bundleTxs) == 0 {
			return nil, nil, nil, errors.New("no bundles to apply")
		}
		if err := w.commitBundle(env, bundleTxs, interrupt); err != nil {
			return nil, nil, nil, err
		}
		blockBundles = mergedBundles
		env.profit.Add(env.profit, resultingBundle.EthSentToCoinbase)
	}

	if len(localTxs) > 0 {
		txs := types.NewTransactionsByPriceAndNonce(env.signer, localTxs, nil, nil, env.header.BaseFee)
		if err := w.commitTransactions(env, txs, interrupt); err != nil {
			return nil, nil, nil, err
		}
	}
	if len(remoteTxs) > 0 {
		txs := types.NewTransactionsByPriceAndNonce(env.signer, remoteTxs, nil, nil, env.header.BaseFee)
		if err := w.commitTransactions(env, txs, interrupt); err != nil {
			return nil, nil, nil, err
		}
	}

	return blockBundles, allBundles, mempoolTxHashes, nil
}

// fillTransactionsAlgoWorker retrieves the pending transactions and bundles from the txpool and fills them
// into the given sealing block.
// Returns error if any, otherwise the bundles that made it into the block and all bundles that passed simulation
func (w *worker) fillTransactionsAlgoWorker(interrupt *int32, env *environment) ([]types.SimulatedBundle, []types.SimulatedBundle, []types.UsedSBundle, map[common.Hash]struct{}, error) {
	// Split the pending transactions into locals and remotes
	// Fill the block with all available pending transactions.
	pending := w.eth.TxPool().Pending(true)
	mempoolTxHashes := make(map[common.Hash]struct{}, len(pending))
	for _, txs := range pending {
		for _, tx := range txs {
			mempoolTxHashes[tx.Hash()] = struct{}{}
		}
	}
	bundlesToConsider, sbundlesToConsider, err := w.getSimulatedBundles(env)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	var (
		newEnv       *environment
		blockBundles []types.SimulatedBundle
		usedSbundle  []types.UsedSBundle
		start        = time.Now()
	)
	switch w.flashbots.algoType {
	case ALGO_GREEDY_BUCKETS:
		priceCutoffPercent := w.config.PriceCutoffPercent
		if !(priceCutoffPercent >= 0 && priceCutoffPercent <= 100) {
			return nil, nil, nil, nil, errors.New("invalid price cutoff percent - must be between 0 and 100")
		}

		algoConf := &algorithmConfig{
			DropRevertibleTxOnErr:  w.config.DiscardRevertibleTxOnErr,
			EnforceProfit:          true,
			ProfitThresholdPercent: defaultProfitThresholdPercent,
			PriceCutoffPercent:     priceCutoffPercent,
		}
		builder := newGreedyBucketsBuilder(
			w.chain, w.chainConfig, algoConf, w.blockList, env,
			w.config.BuilderTxSigningKey, interrupt,
		)

		newEnv, blockBundles, usedSbundle = builder.buildBlock(bundlesToConsider, sbundlesToConsider, pending)
	case ALGO_GREEDY_BUCKETS_MULTISNAP:
		priceCutoffPercent := w.config.PriceCutoffPercent
		if !(priceCutoffPercent >= 0 && priceCutoffPercent <= 100) {
			return nil, nil, nil, nil, errors.New("invalid price cutoff percent - must be between 0 and 100")
		}

		algoConf := &algorithmConfig{
			DropRevertibleTxOnErr:  w.config.DiscardRevertibleTxOnErr,
			EnforceProfit:          true,
			ProfitThresholdPercent: defaultProfitThresholdPercent,
			PriceCutoffPercent:     priceCutoffPercent,
		}
		builder := newGreedyBucketsMultiSnapBuilder(
			w.chain, w.chainConfig, algoConf, w.blockList, env,
			w.config.BuilderTxSigningKey, interrupt,
		)
		newEnv, blockBundles, usedSbundle = builder.buildBlock(bundlesToConsider, sbundlesToConsider, pending)
	case ALGO_GREEDY_MULTISNAP:
		// For greedy multi-snap builder, set algorithm configuration to default values,
		// except DropRevertibleTxOnErr which is passed in from worker config
		algoConf := &algorithmConfig{
			DropRevertibleTxOnErr:  w.config.DiscardRevertibleTxOnErr,
			EnforceProfit:          defaultAlgorithmConfig.EnforceProfit,
			ProfitThresholdPercent: defaultAlgorithmConfig.ProfitThresholdPercent,
		}

		builder := newGreedyMultiSnapBuilder(
			w.chain, w.chainConfig, algoConf, w.blockList, env,
			w.config.BuilderTxSigningKey, interrupt,
		)
		newEnv, blockBundles, usedSbundle = builder.buildBlock(bundlesToConsider, sbundlesToConsider, pending)
	case ALGO_GREEDY:
		fallthrough
	default:
		// For default greedy builder, set algorithm configuration to default values,
		// except DropRevertibleTxOnErr which is passed in from worker config
		algoConf := &algorithmConfig{
			DropRevertibleTxOnErr:  w.config.DiscardRevertibleTxOnErr,
			EnforceProfit:          defaultAlgorithmConfig.EnforceProfit,
			ProfitThresholdPercent: defaultAlgorithmConfig.ProfitThresholdPercent,
		}

		builder := newGreedyBuilder(
			w.chain, w.chainConfig, algoConf, w.blockList,
			env, w.config.BuilderTxSigningKey, interrupt,
		)
		newEnv, blockBundles, usedSbundle = builder.buildBlock(bundlesToConsider, sbundlesToConsider, pending)
	}

	if metrics.EnabledBuilder {
		mergeAlgoTimer.Update(time.Since(start))
	}
	*env = *newEnv

	return blockBundles, bundlesToConsider, usedSbundle, mempoolTxHashes, err
}

func (w *worker) getSimulatedBundles(env *environment) ([]types.SimulatedBundle, []*types.SimSBundle, error) {
	if !w.flashbots.isFlashbots {
		return nil, nil, nil
	}

	bundles, ccBundlesCh := w.eth.TxPool().MevBundles(env.header.Number, env.header.Time)
	sbundles := w.eth.TxPool().GetSBundles(env.header.Number)

	// TODO: consider interrupt
	simBundles, simSBundles, err := w.simulateBundles(env, bundles, sbundles, nil) /* do not consider gas impact of mempool txs as bundles are treated as transactions wrt ordering */
	if err != nil {
		log.Error("Failed to simulate bundles", "err", err)
		return nil, nil, err
	}

	ccBundles := <-ccBundlesCh
	if ccBundles == nil {
		return simBundles, simSBundles, nil
	}

	simCcBundles, _, err := w.simulateBundles(env, ccBundles, nil, nil) /* do not consider gas impact of mempool txs as bundles are treated as transactions wrt ordering */
	if err != nil {
		log.Error("Failed to simulate cc bundles", "err", err)
		return simBundles, simSBundles, nil
	}

	return append(simBundles, simCcBundles...), simSBundles, nil
}

// generateWork generates a sealing block based on the given parameters.
func (w *worker) generateWork(params *generateParams) (*types.Block, *big.Int, error) {
	start := time.Now()
	validatorCoinbase := params.coinbase
	// Set builder coinbase to be passed to beacon header
	params.coinbase = w.coinbase

	work, err := w.prepareWork(params)
	if err != nil {
		return nil, nil, err
	}
	defer work.discard()

	finalizeFn := func(env *environment, orderCloseTime time.Time,
		blockBundles []types.SimulatedBundle, allBundles []types.SimulatedBundle, usedSbundles []types.UsedSBundle, noTxs bool) (*types.Block, *big.Int, error) {
		block, profit, err := w.finalizeBlock(env, params.withdrawals, validatorCoinbase, noTxs)
		if err != nil {
			log.Error("could not finalize block", "err", err)
			return nil, nil, err
		}

		var okSbundles, totalSbundles int
		for _, sb := range usedSbundles {
			if sb.Success {
				okSbundles++
			}
			totalSbundles++
		}

		log.Info("Block finalized and assembled",
			"height", block.Number().String(), "blockProfit", ethIntToFloat(profit),
			"txs", len(env.txs), "bundles", len(blockBundles), "okSbundles", okSbundles, "totalSbundles", totalSbundles,
			"gasUsed", block.GasUsed(), "time", time.Since(start))
		if metrics.EnabledBuilder {
			buildBlockTimer.Update(time.Since(start))
			blockProfitHistogram.Update(profit.Int64())
			blockProfitGauge.Update(profit.Int64())
			culmulativeProfitGauge.Inc(profit.Int64())
			gasUsedGauge.Update(int64(block.GasUsed()))
			transactionNumGauge.Update(int64(len(env.txs)))
		}
		if params.onBlock != nil {
			go params.onBlock(block, profit, orderCloseTime, blockBundles, allBundles, usedSbundles)
		}

		return block, profit, nil
	}

	if params.noTxs {
		return finalizeFn(work, time.Now(), nil, nil, nil, true)
	}

	paymentTxReserve, err := w.proposerTxPrepare(work, &validatorCoinbase)
	if err != nil {
		return nil, nil, err
	}

	orderCloseTime := time.Now()

	blockBundles, allBundles, usedSbundles, mempoolTxHashes, err := w.fillTransactionsSelectAlgo(nil, work)
	if err != nil {
		return nil, nil, err
	}

	// We mark transactions created by the builder as mempool transactions so code validating bundles will not fail
	// for transactions created by the builder such as mev share refunds.
	for _, tx := range work.txs {
		from, err := types.Sender(work.signer, tx)
		if err != nil {
			return nil, nil, err
		}
		if from == work.coinbase {
			mempoolTxHashes[tx.Hash()] = struct{}{}
		}
	}

	err = VerifyBundlesAtomicity(work, blockBundles, allBundles, usedSbundles, mempoolTxHashes)
	if err != nil {
		log.Error("Bundle invariant is violated for built block", "block", work.header.Number, "err", err)
		return nil, nil, err
	}

	// no bundles or tx from mempool
	if len(work.txs) == 0 {
		return finalizeFn(work, orderCloseTime, blockBundles, allBundles, usedSbundles, true)
	}

	err = w.proposerTxCommit(work, &validatorCoinbase, paymentTxReserve)
	if err != nil {
		return nil, nil, err
	}

	return finalizeFn(work, orderCloseTime, blockBundles, allBundles, usedSbundles, false)
}

func (w *worker) finalizeBlock(work *environment, withdrawals types.Withdrawals, validatorCoinbase common.Address, noTxs bool) (*types.Block, *big.Int, error) {
	block, err := w.engine.FinalizeAndAssemble(w.chain, work.header, work.state, work.txs, work.unclelist(), work.receipts, withdrawals)
	if err != nil {
		return nil, nil, err
	}

	if w.config.BuilderTxSigningKey == nil {
		return block, big.NewInt(0), nil
	}

	if noTxs {
		return block, big.NewInt(0), nil
	}

	blockProfit, err := w.checkProposerPayment(work, validatorCoinbase)
	if err != nil {
		return nil, nil, err
	}

	return block, blockProfit, nil
}

func (w *worker) checkProposerPayment(work *environment, validatorCoinbase common.Address) (*big.Int, error) {
	if len(work.txs) == 0 {
		return nil, errors.New("no proposer payment tx")
	} else if len(work.receipts) == 0 {
		return nil, errors.New("no proposer payment receipt")
	}

	lastTx := work.txs[len(work.txs)-1]
	receipt := work.receipts[len(work.receipts)-1]
	if receipt.TxHash != lastTx.Hash() || receipt.Status != types.ReceiptStatusSuccessful {
		log.Error("proposer payment not successful!", "lastTx", lastTx, "receipt", receipt)
		return nil, errors.New("last transaction is not proposer payment")
	}
	lastTxTo := lastTx.To()
	if lastTxTo == nil || *lastTxTo != validatorCoinbase {
		log.Error("last transaction is not to the proposer!", "lastTx", lastTx)
		return nil, errors.New("last transaction is not proposer payment")
	}

	return new(big.Int).Set(lastTx.Value()), nil
}

// commitWork generates several new sealing tasks based on the parent block
// and submit them to the sealer.
func (w *worker) commitWork(interrupt *int32, noempty bool, timestamp int64) {
	start := time.Now()

	// Set the coinbase if the worker is running or it's required
	var coinbase common.Address
	if w.isRunning() {
		coinbase = w.etherbase()
		if coinbase == (common.Address{}) {
			log.Error("Refusing to mine without etherbase")
			return
		}
	}
	work, err := w.prepareWork(&generateParams{
		timestamp: uint64(timestamp),
		coinbase:  coinbase,
	})
	if err != nil {
		return
	}
	// Create an empty block based on temporary copied state for
	// sealing in advance without waiting block execution finished.
	if !noempty && atomic.LoadUint32(&w.noempty) == 0 {
		w.commit(work.copy(), nil, false, start)
	}

	// Fill pending transactions from the txpool
	_, _, _, _, err = w.fillTransactionsSelectAlgo(interrupt, work)
	switch {
	case err == nil:
		// The entire block is filled, decrease resubmit interval in case
		// of current interval is larger than the user-specified one.
		w.resubmitAdjustCh <- &intervalAdjust{inc: false}

	case errors.Is(err, errBlockInterruptedByRecommit):
		// Notify resubmit loop to increase resubmitting interval if the
		// interruption is due to frequent commits.
		gaslimit := work.header.GasLimit
		ratio := float64(gaslimit-work.gasPool.Gas()) / float64(gaslimit)
		if ratio < 0.1 {
			ratio = 0.1
		}
		w.resubmitAdjustCh <- &intervalAdjust{
			ratio: ratio,
			inc:   true,
		}
	default:
		work.discard()
		return
	}
	// Submit the generated block for consensus sealing.
	w.commit(work.copy(), w.fullTaskHook, true, start)

	// Swap out the old work with the new one, terminating any leftover
	// prefetcher processes in the mean time and starting a new one.
	if w.current != nil {
		w.current.discard()
	}
	w.current = work
}

// commit runs any post-transaction state modifications, assembles the final block
// and commits new work if consensus engine is running.
// Note the assumption is held that the mutation is allowed to the passed env, do
// the deep copy first.
func (w *worker) commit(env *environment, interval func(), update bool, start time.Time) error {
	if w.isRunning() {
		if interval != nil {
			interval()
		}
		// Create a local environment copy, avoid the data race with snapshot state.
		// https://github.com/ethereum/go-ethereum/issues/24299
		env := env.copy()
		// Withdrawals are set to nil here, because this is only called in PoW.
		block, err := w.engine.FinalizeAndAssemble(w.chain, env.header, env.state, env.txs, env.unclelist(), env.receipts, nil)
		if err != nil {
			return err
		}
		// If we're post merge, just ignore
		if !w.isTTDReached(block.Header()) {
			select {
			case w.taskCh <- &task{receipts: env.receipts, state: env.state, block: block, createdAt: time.Now(), profit: env.profit, isFlashbots: w.flashbots.isFlashbots, worker: w.flashbots.maxMergedBundles}:
				w.unconfirmed.Shift(block.NumberU64() - 1)

				fees := totalFees(block, env)
				log.Info("Commit new sealing work", "number", block.Number(), "sealhash", w.engine.SealHash(block.Header()),
					"uncles", len(env.uncles), "txs", env.tcount, "gas", block.GasUsed(), "fees", ethIntToFloat(fees),
					"elapsed", common.PrettyDuration(time.Since(start)), "isFlashbots", w.flashbots.isFlashbots,
					"worker", w.flashbots.maxMergedBundles)

			case <-w.exitCh:
				log.Info("Worker has exited")
			}
		}
	}
	if update {
		w.updateSnapshot(env)
	}
	return nil
}

// getSealingBlock generates the sealing block based on the given parameters.
// The generation result will be passed back via the given channel no matter
// the generation itself succeeds or not.
func (w *worker) getSealingBlock(parent common.Hash, timestamp uint64, coinbase common.Address, gasLimit uint64, random common.Hash, withdrawals types.Withdrawals, noTxs bool, blockHook BlockHookFn) (*types.Block, *big.Int, error) {
	req := &getWorkReq{
		params: &generateParams{
			timestamp:   timestamp,
			forceTime:   true,
			parentHash:  parent,
			coinbase:    coinbase,
			gasLimit:    gasLimit,
			random:      random,
			withdrawals: withdrawals,
			noUncle:     true,
			noTxs:       noTxs,
			onBlock:     blockHook,
		},
		result: make(chan *newPayloadResult, 1),
	}
	select {
	case w.getWorkCh <- req:
		result := <-req.result
		if result.err != nil {
			return nil, nil, result.err
		}
		return result.block, result.fees, nil
	case <-w.exitCh:
		return nil, nil, errors.New("miner closed")
	}
}

// isTTDReached returns the indicator if the given block has reached the total
// terminal difficulty for The Merge transition.
func (w *worker) isTTDReached(header *types.Header) bool {
	td, ttd := w.chain.GetTd(header.ParentHash, header.Number.Uint64()-1), w.chain.Config().TerminalTotalDifficulty
	return td != nil && ttd != nil && td.Cmp(ttd) >= 0
}

type simulatedBundle = types.SimulatedBundle

func (w *worker) generateFlashbotsBundle(env *environment, bundles []types.MevBundle, pendingTxs map[common.Address]types.Transactions) (types.Transactions, simulatedBundle, []types.SimulatedBundle, int, []types.SimulatedBundle, error) {
	simulatedBundles, _, err := w.simulateBundles(env, bundles, nil, pendingTxs)
	if err != nil {
		return nil, simulatedBundle{}, nil, 0, nil, err
	}

	sort.SliceStable(simulatedBundles, func(i, j int) bool {
		return simulatedBundles[j].MevGasPrice.Cmp(simulatedBundles[i].MevGasPrice) < 0
	})

	bundleTxs, bundle, mergedBundles, numBundles, err := w.mergeBundles(env, simulatedBundles, pendingTxs)
	return bundleTxs, bundle, mergedBundles, numBundles, simulatedBundles, err
}

func (w *worker) mergeBundles(env *environment, bundles []simulatedBundle, pendingTxs map[common.Address]types.Transactions) (types.Transactions, simulatedBundle, []types.SimulatedBundle, int, error) {
	mergedBundles := []types.SimulatedBundle{}
	finalBundle := types.Transactions{}

	currentState := env.state.Copy()
	gasPool := new(core.GasPool).AddGas(env.header.GasLimit)

	var prevState *state.StateDB
	var prevGasPool *core.GasPool

	mergedBundle := simulatedBundle{
		TotalEth:          new(big.Int),
		EthSentToCoinbase: new(big.Int),
	}

	count := 0
	for _, bundle := range bundles {
		prevState = currentState.Copy()
		prevGasPool = new(core.GasPool).AddGas(gasPool.Gas())

		// the floor gas price is 99/100 what was simulated at the top of the block
		floorGasPrice := new(big.Int).Mul(bundle.MevGasPrice, big.NewInt(99))
		floorGasPrice = floorGasPrice.Div(floorGasPrice, big.NewInt(100))

		simmed, err := w.computeBundleGas(env, bundle.OriginalBundle, currentState, gasPool, pendingTxs, len(finalBundle))
		if err != nil || simmed.MevGasPrice.Cmp(floorGasPrice) <= 0 {
			currentState = prevState
			gasPool = prevGasPool
			continue
		}

		log.Info("Included bundle", "ethToCoinbase", ethIntToFloat(simmed.TotalEth), "gasUsed", simmed.TotalGasUsed, "bundleScore", simmed.MevGasPrice, "bundleLength", len(simmed.OriginalBundle.Txs), "worker", w.flashbots.maxMergedBundles)
		mergedBundles = append(mergedBundles, simmed)
		finalBundle = append(finalBundle, bundle.OriginalBundle.Txs...)
		mergedBundle.TotalEth.Add(mergedBundle.TotalEth, simmed.TotalEth)
		mergedBundle.EthSentToCoinbase.Add(mergedBundle.EthSentToCoinbase, simmed.EthSentToCoinbase)
		mergedBundle.TotalGasUsed += simmed.TotalGasUsed
		count++

		if count >= w.flashbots.maxMergedBundles {
			break
		}
	}

	if len(finalBundle) == 0 || count != w.flashbots.maxMergedBundles {
		return nil, simulatedBundle{}, nil, count, nil
	}

	return finalBundle, simulatedBundle{
		MevGasPrice:       new(big.Int).Div(mergedBundle.TotalEth, new(big.Int).SetUint64(mergedBundle.TotalGasUsed)),
		TotalEth:          mergedBundle.TotalEth,
		EthSentToCoinbase: mergedBundle.EthSentToCoinbase,
		TotalGasUsed:      mergedBundle.TotalGasUsed,
	}, mergedBundles, count, nil
}

func (w *worker) simulateBundles(env *environment, bundles []types.MevBundle, sbundles []*types.SBundle, pendingTxs map[common.Address]types.Transactions) ([]simulatedBundle, []*types.SimSBundle, error) {
	start := time.Now()
	headerHash := env.header.Hash()
	simCache := w.flashbots.bundleCache.GetBundleCache(headerHash)

	simResult := make([]*simulatedBundle, len(bundles))
	sbSimResult := make([]*types.SimSBundle, len(sbundles))

	var wg sync.WaitGroup
	for i, bundle := range bundles {
		if simmed, ok := simCache.GetSimulatedBundle(bundle.Hash); ok {
			simResult[i] = simmed
			continue
		}

		wg.Add(1)
		go func(idx int, bundle types.MevBundle, state *state.StateDB) {
			defer wg.Done()

			start := time.Now()
			if metrics.EnabledBuilder {
				bundleTxNumHistogram.Update(int64(len(bundle.Txs)))
			}

			if len(bundle.Txs) == 0 {
				return
			}
			gasPool := new(core.GasPool).AddGas(env.header.GasLimit)
			simmed, err := w.computeBundleGas(env, bundle, state, gasPool, pendingTxs, 0)

			if metrics.EnabledBuilder {
				simulationMeter.Mark(1)
			}

			if err != nil {
				if metrics.EnabledBuilder {
					simulationRevertedMeter.Mark(1)
					failedBundleSimulationTimer.UpdateSince(start)
				}

				log.Trace("Error computing gas for a bundle", "error", err)
				return
			}
			simResult[idx] = &simmed

			if metrics.EnabledBuilder {
				simulationCommittedMeter.Mark(1)
				successfulBundleSimulationTimer.UpdateSince(start)
			}
		}(i, bundle, env.state.Copy())
	}

	for i, sbundle := range sbundles {
		if simmed, ok := simCache.GetSimSBundle(sbundle.Hash()); ok {
			sbSimResult[i] = simmed
			continue
		}

		wg.Add(1)
		go func(idx int, sbundle *types.SBundle, state *state.StateDB) {
			defer wg.Done()

			start := time.Now()
			if metrics.EnabledBuilder {
				bundleTxNumHistogram.Update(int64(len(sbundle.Body)))
			}

			gp := new(core.GasPool).AddGas(env.header.GasLimit)

			tmpGasUsed := uint64(0)
			config := *w.chain.GetVMConfig()
			var tracer *logger.AccountTouchTracer
			if len(w.blockList) != 0 {
				tracer = logger.NewAccountTouchTracer()
				config.Tracer = tracer
				config.Debug = true
			}
			simRes, err := core.SimBundle(w.chainConfig, w.chain, &env.coinbase, gp, state, env.header, sbundle, 0, &tmpGasUsed, config, false)
			if metrics.EnabledBuilder {
				simulationMeter.Mark(1)
			}
			if err != nil {
				if metrics.EnabledBuilder {
					simulationRevertedMeter.Mark(1)
					failedBundleSimulationTimer.UpdateSince(start)
				}
				return
			}
			if len(w.blockList) != 0 {
				for _, address := range tracer.TouchedAddresses() {
					if _, in := w.blockList[address]; in {
						return
					}
				}
			}

			result := &types.SimSBundle{
				Bundle:      sbundle,
				MevGasPrice: simRes.MevGasPrice,
				Profit:      simRes.TotalProfit,
			}
			sbSimResult[idx] = result

			if metrics.EnabledBuilder {
				simulationCommittedMeter.Mark(1)
				successfulBundleSimulationTimer.UpdateSince(start)
			}
		}(i, sbundle, env.state.Copy())
	}

	wg.Wait()

	simCache.UpdateSimulatedBundles(simResult, bundles)
	simulatedBundles := make([]simulatedBundle, 0, len(bundles))
	for _, bundle := range simResult {
		if bundle != nil {
			simulatedBundles = append(simulatedBundles, *bundle)
		}
	}

	simCache.UpdateSimSBundle(sbSimResult, sbundles)
	simulatedSbundle := make([]*types.SimSBundle, 0, len(sbundles))
	for _, sbundle := range sbSimResult {
		if sbundle != nil {
			simulatedSbundle = append(simulatedSbundle, sbundle)
		}
	}

	log.Debug("Simulated bundles", "block", env.header.Number, "allBundles", len(bundles), "okBundles", len(simulatedBundles),
		"allSbundles", len(sbundles), "okSbundles", len(simulatedSbundle), "time", time.Since(start))
	if metrics.EnabledBuilder {
		blockBundleSimulationTimer.Update(time.Since(start))
	}
	return simulatedBundles, simulatedSbundle, nil
}

func containsHash(arr []common.Hash, match common.Hash) bool {
	for _, elem := range arr {
		if elem == match {
			return true
		}
	}
	return false
}

// Compute the adjusted gas price for a whole bundle
// Done by calculating all gas spent, adding transfers to the coinbase, and then dividing by gas used
func (w *worker) computeBundleGas(
	env *environment, bundle types.MevBundle, state *state.StateDB, gasPool *core.GasPool,
	pendingTxs map[common.Address]types.Transactions, currentTxCount int,
) (simulatedBundle, error) {
	var totalGasUsed uint64 = 0
	var tempGasUsed uint64
	gasFees := new(big.Int)

	ethSentToCoinbase := new(big.Int)

	for i, tx := range bundle.Txs {
		if env.header.BaseFee != nil && tx.Type() == 2 {
			// Sanity check for extremely large numbers
			if tx.GasFeeCap().BitLen() > 256 {
				return simulatedBundle{}, core.ErrFeeCapVeryHigh
			}
			if tx.GasTipCap().BitLen() > 256 {
				return simulatedBundle{}, core.ErrTipVeryHigh
			}
			// Ensure gasFeeCap is greater than or equal to gasTipCap.
			if tx.GasFeeCapIntCmp(tx.GasTipCap()) < 0 {
				return simulatedBundle{}, core.ErrTipAboveFeeCap
			}
		}

		state.SetTxContext(tx.Hash(), i+currentTxCount)
		coinbaseBalanceBefore := state.GetBalance(env.coinbase)

		config := *w.chain.GetVMConfig()
		var tracer *logger.AccountTouchTracer
		if len(w.blockList) != 0 {
			tracer = logger.NewAccountTouchTracer()
			config.Tracer = tracer
			config.Debug = true
		}
		receipt, err := core.ApplyTransaction(w.chainConfig, w.chain, &env.coinbase, gasPool, state, env.header, tx, &tempGasUsed, config, nil)
		if err != nil {
			return simulatedBundle{}, err
		}
		if receipt.Status == types.ReceiptStatusFailed && !containsHash(bundle.RevertingTxHashes, receipt.TxHash) {
			return simulatedBundle{}, errors.New("failed tx")
		}
		if len(w.blockList) != 0 {
			for _, address := range tracer.TouchedAddresses() {
				if _, in := w.blockList[address]; in {
					return simulatedBundle{}, errBlocklistViolation
				}
			}
		}

		totalGasUsed += receipt.GasUsed

		from, err := types.Sender(env.signer, tx)
		if err != nil {
			return simulatedBundle{}, err
		}

		txInPendingPool := false
		if accountTxs, ok := pendingTxs[from]; ok {
			// check if tx is in pending pool
			txNonce := tx.Nonce()

			for _, accountTx := range accountTxs {
				if accountTx.Nonce() == txNonce {
					txInPendingPool = true
					break
				}
			}
		}

		gasUsed := new(big.Int).SetUint64(receipt.GasUsed)
		gasPrice, err := tx.EffectiveGasTip(env.header.BaseFee)
		if err != nil {
			return simulatedBundle{}, err
		}
		gasFeesTx := gasUsed.Mul(gasUsed, gasPrice)
		coinbaseBalanceAfter := state.GetBalance(env.coinbase)
		coinbaseDelta := big.NewInt(0).Sub(coinbaseBalanceAfter, coinbaseBalanceBefore)
		coinbaseDelta.Sub(coinbaseDelta, gasFeesTx)
		ethSentToCoinbase.Add(ethSentToCoinbase, coinbaseDelta)

		if !txInPendingPool {
			// If tx is not in pending pool, count the gas fees
			gasFees.Add(gasFees, gasFeesTx)
		}
	}

	totalEth := new(big.Int).Add(ethSentToCoinbase, gasFees)

	return simulatedBundle{
		MevGasPrice:       new(big.Int).Div(totalEth, new(big.Int).SetUint64(totalGasUsed)),
		TotalEth:          totalEth,
		EthSentToCoinbase: ethSentToCoinbase,
		TotalGasUsed:      totalGasUsed,
		OriginalBundle:    bundle,
	}, nil
}

// copyReceipts makes a deep copy of the given receipts.
func copyReceipts(receipts []*types.Receipt) []*types.Receipt {
	result := make([]*types.Receipt, len(receipts))
	for i, l := range receipts {
		cpy := *l
		result[i] = &cpy
	}
	return result
}

// postSideBlock fires a side chain event, only use it for testing.
func (w *worker) postSideBlock(event core.ChainSideEvent) {
	select {
	case w.chainSideCh <- event:
	case <-w.exitCh:
	}
}

// ethIntToFloat is for formatting a big.Int in wei to eth
func ethIntToFloat(eth *big.Int) *big.Float {
	if eth == nil {
		return big.NewFloat(0)
	}
	return new(big.Float).Quo(new(big.Float).SetInt(eth), new(big.Float).SetInt(big.NewInt(params.Ether)))
}

// totalFees computes total consumed miner fees in ETH. Block transactions and receipts have to have the same order.
func totalFees(block *types.Block, env *environment) *big.Int {
	return new(big.Int).Set(env.profit)
}

type proposerTxReservation struct {
	builderBalance *big.Int
	reservedGas    uint64
	isEOA          bool
}

func (w *worker) proposerTxPrepare(env *environment, validatorCoinbase *common.Address) (*proposerTxReservation, error) {
	if validatorCoinbase == nil || w.config.BuilderTxSigningKey == nil {
		return nil, nil
	}

	w.mu.Lock()
	sender := w.coinbase
	w.mu.Unlock()
	builderBalance := env.state.GetBalance(sender)

	chainData := chainData{w.chainConfig, w.chain, w.blockList}
	gas, isEOA, err := estimatePayoutTxGas(env, sender, *validatorCoinbase, w.config.BuilderTxSigningKey, chainData)
	if err != nil {
		return nil, fmt.Errorf("failed to estimate proposer payout gas: %w", err)
	}

	if err := env.gasPool.SubGas(gas); err != nil {
		return nil, err
	}

	return &proposerTxReservation{
		builderBalance: builderBalance,
		reservedGas:    gas,
		isEOA:          isEOA,
	}, nil
}

func (w *worker) proposerTxCommit(env *environment, validatorCoinbase *common.Address, reserve *proposerTxReservation) error {
	if reserve == nil || validatorCoinbase == nil {
		return nil
	}

	w.mu.Lock()
	sender := w.coinbase
	w.mu.Unlock()
	builderBalance := env.state.GetBalance(sender)

	availableFunds := new(big.Int).Sub(builderBalance, reserve.builderBalance)
	if availableFunds.Sign() <= 0 {
		return errors.New("builder balance decreased")
	}

	env.gasPool.AddGas(reserve.reservedGas)
	chainData := chainData{w.chainConfig, w.chain, w.blockList}
	_, err := insertPayoutTx(env, sender, *validatorCoinbase, reserve.reservedGas, reserve.isEOA, availableFunds, w.config.BuilderTxSigningKey, chainData)
	if err != nil {
		return err
	}
	return nil
}

// signalToErr converts the interruption signal to a concrete error type for return.
// The given signal must be a valid interruption signal.
func signalToErr(signal int32) error {
	switch signal {
	case commitInterruptNewHead:
		return errBlockInterruptedByNewHead
	case commitInterruptResubmit:
		return errBlockInterruptedByRecommit
	case commitInterruptTimeout:
		return errBlockInterruptedByTimeout
	default:
		panic(fmt.Errorf("undefined signal %d", signal))
	}
}
