// Code generated by fastssz. DO NOT EDIT.
// Hash: cb7006db7808ee76b3c3bcadc1a063f3beffa6f9f14fcc7a3d6f91c2cd700fb1
// Version: 0.1.3
package validation

import (
	builderApiDeneb "github.com/attestantio/go-builder-client/api/deneb"
	builderApiV1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	ssz "github.com/ferranbt/fastssz"
)

// MarshalSSZ ssz marshals the BuilderBlockValidationRequestV3 object
func (b *BuilderBlockValidationRequestV3) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(b)
}

// MarshalSSZTo ssz marshals the BuilderBlockValidationRequestV3 object to a target array
func (b *BuilderBlockValidationRequestV3) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	offset := int(380)

	// Field (0) 'Message'
	if b.Message == nil {
		b.Message = new(builderApiV1.BidTrace)
	}
	if dst, err = b.Message.MarshalSSZTo(dst); err != nil {
		return
	}

	// Offset (1) 'ExecutionPayload'
	dst = ssz.WriteOffset(dst, offset)
	if b.ExecutionPayload == nil {
		b.ExecutionPayload = new(deneb.ExecutionPayload)
	}
	offset += b.ExecutionPayload.SizeSSZ()

	// Offset (2) 'BlobsBundle'
	dst = ssz.WriteOffset(dst, offset)
	if b.BlobsBundle == nil {
		b.BlobsBundle = new(builderApiDeneb.BlobsBundle)
	}
	offset += b.BlobsBundle.SizeSSZ()

	// Field (3) 'Signature'
	dst = append(dst, b.Signature[:]...)

	// Field (4) 'ParentBeaconBlockRoot'
	dst = append(dst, b.ParentBeaconBlockRoot[:]...)

	// Field (5) 'RegisteredGasLimit'
	dst = ssz.MarshalUint64(dst, b.RegisteredGasLimit)

	// Field (1) 'ExecutionPayload'
	if dst, err = b.ExecutionPayload.MarshalSSZTo(dst); err != nil {
		return
	}

	// Field (2) 'BlobsBundle'
	if dst, err = b.BlobsBundle.MarshalSSZTo(dst); err != nil {
		return
	}

	return
}

// UnmarshalSSZ ssz unmarshals the BuilderBlockValidationRequestV3 object
func (b *BuilderBlockValidationRequestV3) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 380 {
		return ssz.ErrSize
	}

	tail := buf
	var o1, o2 uint64

	// Field (0) 'Message'
	if b.Message == nil {
		b.Message = new(builderApiV1.BidTrace)
	}
	if err = b.Message.UnmarshalSSZ(buf[0:236]); err != nil {
		return err
	}

	// Offset (1) 'ExecutionPayload'
	if o1 = ssz.ReadOffset(buf[236:240]); o1 > size {
		return ssz.ErrOffset
	}

	if o1 < 380 {
		return ssz.ErrInvalidVariableOffset
	}

	// Offset (2) 'BlobsBundle'
	if o2 = ssz.ReadOffset(buf[240:244]); o2 > size || o1 > o2 {
		return ssz.ErrOffset
	}

	// Field (3) 'Signature'
	copy(b.Signature[:], buf[244:340])

	// Field (4) 'ParentBeaconBlockRoot'
	copy(b.ParentBeaconBlockRoot[:], buf[340:372])

	// Field (5) 'RegisteredGasLimit'
	b.RegisteredGasLimit = ssz.UnmarshallUint64(buf[372:380])

	// Field (1) 'ExecutionPayload'
	{
		buf = tail[o1:o2]
		if b.ExecutionPayload == nil {
			b.ExecutionPayload = new(deneb.ExecutionPayload)
		}
		if err = b.ExecutionPayload.UnmarshalSSZ(buf); err != nil {
			return err
		}
	}

	// Field (2) 'BlobsBundle'
	{
		buf = tail[o2:]
		if b.BlobsBundle == nil {
			b.BlobsBundle = new(builderApiDeneb.BlobsBundle)
		}
		if err = b.BlobsBundle.UnmarshalSSZ(buf); err != nil {
			return err
		}
	}
	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the BuilderBlockValidationRequestV3 object
func (b *BuilderBlockValidationRequestV3) SizeSSZ() (size int) {
	size = 380

	// Field (1) 'ExecutionPayload'
	if b.ExecutionPayload == nil {
		b.ExecutionPayload = new(deneb.ExecutionPayload)
	}
	size += b.ExecutionPayload.SizeSSZ()

	// Field (2) 'BlobsBundle'
	if b.BlobsBundle == nil {
		b.BlobsBundle = new(builderApiDeneb.BlobsBundle)
	}
	size += b.BlobsBundle.SizeSSZ()

	return
}

// HashTreeRoot ssz hashes the BuilderBlockValidationRequestV3 object
func (b *BuilderBlockValidationRequestV3) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(b)
}

// HashTreeRootWith ssz hashes the BuilderBlockValidationRequestV3 object with a hasher
func (b *BuilderBlockValidationRequestV3) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'Message'
	if b.Message == nil {
		b.Message = new(builderApiV1.BidTrace)
	}
	if err = b.Message.HashTreeRootWith(hh); err != nil {
		return
	}

	// Field (1) 'ExecutionPayload'
	if err = b.ExecutionPayload.HashTreeRootWith(hh); err != nil {
		return
	}

	// Field (2) 'BlobsBundle'
	if err = b.BlobsBundle.HashTreeRootWith(hh); err != nil {
		return
	}

	// Field (3) 'Signature'
	hh.PutBytes(b.Signature[:])

	// Field (4) 'ParentBeaconBlockRoot'
	hh.PutBytes(b.ParentBeaconBlockRoot[:])

	// Field (5) 'RegisteredGasLimit'
	hh.PutUint64(b.RegisteredGasLimit)

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the BuilderBlockValidationRequestV3 object
func (b *BuilderBlockValidationRequestV3) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(b)
}