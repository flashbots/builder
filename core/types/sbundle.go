package types

import (
	"errors"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
	"golang.org/x/crypto/sha3"
)

var (
	ErrIncorrectRefundConfig = errors.New("incorrect refund config")
)

// SBundle is a bundle of transactions that must be executed atomically
// unlike ordinary bundle it also supports refunds
type SBundle struct {
	Inclusion BundleInclusion
	Body      []BundleBody
	Validity  BundleValidity

	hash atomic.Value
}

type BundleInclusion struct {
	BlockNumber    uint64
	MaxBlockNumber uint64
}

type BundleBody struct {
	Tx        *Transaction
	Bundle    *SBundle
	CanRevert bool
}

type BundleValidity struct {
	Refund       []RefundConstraint `json:"refund,omitempty"`
	RefundConfig []RefundConfig     `json:"refundConfig,omitempty"`
}

type RefundConstraint struct {
	BodyIdx int `json:"bodyIdx"`
	Percent int `json:"percent"`
}

type RefundConfig struct {
	Address common.Address `json:"address"`
	Percent int            `json:"percent"`
}

type BundlePrivacy struct {
	RefundAddress common.Address
}

func (b *SBundle) Hash() common.Hash {
	if hash := b.hash.Load(); hash != nil {
		return hash.(common.Hash)
	}

	bodyHashes := make([]common.Hash, len(b.Body))
	for i, body := range b.Body {
		if body.Tx != nil {
			bodyHashes[i] = body.Tx.Hash()
		} else if body.Bundle != nil {
			bodyHashes[i] = body.Bundle.Hash()
		}
	}

	var h common.Hash
	if len(bodyHashes) == 1 {
		h = bodyHashes[0]
	} else {
		hasher := sha3.NewLegacyKeccak256()
		for _, h := range bodyHashes {
			hasher.Write(h[:])
		}
		h = common.BytesToHash(hasher.Sum(nil))
	}
	b.hash.Store(h)
	return h
}

type SimSBundle struct {
	Bundle *SBundle
	// MevGasPrice = (total coinbase profit) / (gas used)
	MevGasPrice *uint256.Int
	Profit      *uint256.Int
}

func GetRefundConfig(body *BundleBody, signer Signer) ([]RefundConfig, error) {
	if body.Tx != nil {
		address, err := signer.Sender(body.Tx)
		if err != nil {
			return nil, err
		}
		return []RefundConfig{{Address: address, Percent: 100}}, nil
	}
	if bundle := body.Bundle; bundle != nil {
		if len(bundle.Validity.RefundConfig) > 0 {
			return bundle.Validity.RefundConfig, nil
		} else {
			if len(bundle.Body) == 0 {
				return nil, ErrIncorrectRefundConfig
			}
			return GetRefundConfig(&bundle.Body[0], signer)
		}
	}
	return nil, ErrIncorrectRefundConfig
}

// UsedSBundle is a bundle that was used in the block building
type UsedSBundle struct {
	Bundle  *SBundle
	Success bool
}
