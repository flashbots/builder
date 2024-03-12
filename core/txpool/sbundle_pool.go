package txpool

// TODO: cancel sbundles, fetch them from the db

import (
	"errors"
	"math/big"
	"sync"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

const (
	maxSBundleRange   = 30
	maxSBundleNesting = 1

	// txSlotSize is used to calculate how many data slots a single transaction
	// takes up based on its size. The slots are used as DoS protection, ensuring
	// that validating a new transaction remains a constant operation (in reality
	// O(maxslots), where max slots are 4 currently).
	txSlotSize = 32 * 1024
	// txMaxSize is the maximum size a single transaction can have. This field has
	// non-trivial consequences: larger transactions are significantly harder and
	// more expensive to propagate; larger transactions also take more resources
	// to validate whether they fit into the pool or not.
	txMaxSize = 4 * txSlotSize // 128KB
	// blobTxMaxSize is the maximum size a single transaction can have, outside
	// the included blobs. Since blob transactions are pulled instead of pushed,
	// and only a small metadata is kept in ram, the rest is on disk, there is
	// no critical limit that should be enforced. Still, capping it to some sane
	// limit can never hurt.
	blobTxMaxSize = 1024 * 1024
)

var (
	ErrInvalidInclusion   = errors.New("invalid inclusion")
	ErrBundleTooDeep      = errors.New("bundle too deep")
	ErrInvalidBody        = errors.New("invalid body")
	ErrInvalidConstraints = errors.New("invalid constraints")
)

type SBundlePool struct {
	mu sync.Mutex

	bundles map[common.Hash]*types.SBundle
	byBlock map[uint64][]*types.SBundle

	// bundles that were cancelled and their max valid block
	cancelled         map[common.Hash]struct{}
	cancelledMaxBlock map[uint64][]common.Hash

	signer types.Signer

	chainconfig *params.ChainConfig
	currentHead atomic.Pointer[types.Header]
}

func NewSBundlePool(chainConfig *params.ChainConfig) *SBundlePool {
	return &SBundlePool{
		bundles:           make(map[common.Hash]*types.SBundle),
		byBlock:           make(map[uint64][]*types.SBundle),
		cancelled:         make(map[common.Hash]struct{}),
		cancelledMaxBlock: make(map[uint64][]common.Hash),
		signer:            types.LatestSigner(chainConfig),
		chainconfig:       chainConfig,
	}
}

func (p *SBundlePool) ResetPoolData(head *types.Header) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.currentHead.Store(head)
}

func (p *SBundlePool) Add(bundle *types.SBundle) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, ok := p.bundles[bundle.Hash()]; ok {
		return nil
	}

	if err := p.validateSBundle(0, bundle); err != nil {
		return err
	}

	p.bundles[bundle.Hash()] = bundle
	for b := bundle.Inclusion.BlockNumber; b <= bundle.Inclusion.MaxBlockNumber; b++ {
		p.byBlock[b] = append(p.byBlock[b], bundle)
	}
	return nil
}

func (p *SBundlePool) GetSBundles(nextBlock uint64) []*types.SBundle {
	p.mu.Lock()
	defer p.mu.Unlock()

	// remove old blocks
	for b, el := range p.byBlock {
		if b < nextBlock {
			for _, bundle := range el {
				if bundle.Inclusion.MaxBlockNumber < nextBlock {
					delete(p.bundles, bundle.Hash())
				}
				delete(p.bundles, bundle.Hash())
			}
			delete(p.byBlock, b)
		}
	}

	// remove expired cancelled bundles
	for b, el := range p.cancelledMaxBlock {
		if b < nextBlock {
			for _, hash := range el {
				delete(p.cancelled, hash)
			}
			delete(p.cancelledMaxBlock, b)
		}
	}

	// filter cancelled bundles and dependent bundles
	var res []*types.SBundle
	for _, bundle := range p.byBlock[nextBlock] {
		if isBundleCancelled(bundle, p.cancelled) {
			continue
		}
		res = append(res, bundle)
	}

	return res
}

func (p *SBundlePool) validateSBundle(level int, b *types.SBundle) error {
	if level > maxSBundleNesting {
		return ErrBundleTooDeep
	}
	// inclusion
	if b.Inclusion.BlockNumber > b.Inclusion.MaxBlockNumber {
		return ErrInvalidInclusion
	}
	if b.Inclusion.MaxBlockNumber-b.Inclusion.BlockNumber > maxSBundleRange {
		return ErrInvalidInclusion
	}

	// body
	for _, el := range b.Body {
		if el.Tx != nil {
			if err := p.validateTx(el.Tx); err != nil {
				return err
			}
		} else if el.Bundle != nil {
			if err := p.validateSBundle(level+1, el.Bundle); err != nil {
				return err
			}
		} else {
			return ErrInvalidBody
		}
	}

	// constraints
	if len(b.Validity.Refund) > len(b.Body) {
		return ErrInvalidConstraints
	}

	usedConstraints := make([]bool, len(b.Body))
	totalRefundPercent := 0
	for _, el := range b.Validity.Refund {
		if el.BodyIdx >= len(b.Body) {
			return ErrInvalidConstraints
		}
		if usedConstraints[el.BodyIdx] {
			return ErrInvalidConstraints
		}
		usedConstraints[el.BodyIdx] = true
		totalRefundPercent += el.Percent
	}
	if totalRefundPercent > 100 {
		return ErrInvalidConstraints
	}

	return nil
}

// same as core/tx_pool.go but we don't check for gas price and nonce
func (p *SBundlePool) validateTx(tx *types.Transaction) error {
	opts := &ValidationOptions{
		Config: p.chainconfig,
		MinTip: new(big.Int),
	}

	if tx.Type() == types.BlobTxType {
		opts.MaxSize = blobTxMaxSize
		opts.Accept = 1 << types.BlobTxType
	} else {
		opts.MaxSize = txMaxSize
		opts.Accept = 0 |
			1<<types.LegacyTxType |
			1<<types.AccessListTxType |
			1<<types.DynamicFeeTxType
	}

	if err := ValidateTransaction(tx, p.currentHead.Load(), p.signer, opts); err != nil {
		return err
	}
	return nil
}

func (b *SBundlePool) Cancel(hashes []common.Hash) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for _, hash := range hashes {
		if bundle, ok := b.bundles[hash]; ok {
			maxBlock := bundle.Inclusion.MaxBlockNumber
			b.cancelled[hash] = struct{}{}
			b.cancelledMaxBlock[maxBlock] = append(b.cancelledMaxBlock[maxBlock], hash)
		}
	}
}

func isBundleCancelled(bundle *types.SBundle, cancelled map[common.Hash]struct{}) bool {
	if _, ok := cancelled[bundle.Hash()]; ok {
		return true
	}
	for _, el := range bundle.Body {
		if el.Bundle != nil {
			if isBundleCancelled(el.Bundle, cancelled) {
				return true
			}
		}
	}
	return false
}
