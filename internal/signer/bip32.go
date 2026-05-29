// Package signer implements the CoinDock signer/deriver service contract
// (see coindock docs api/03-signer-service-api.md). This file provides BIP32
// public-key derivation (CKDpub) used to derive watch-only deposit addresses
// from an account xpub — no private key material is involved.
//
// The elliptic-curve math is done with the same secp256k1 implementation the
// node signs with (github.com/decred/dcrd/dcrec/secp256k1/v4), and the
// derivation is proven against the canonical BIP32 test vectors in
// bip32_test.go.
package signer

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/computervirtualservices/malairte/internal/crypto"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// hardenedOffset is the first hardened child index (2^31). Hardened children
// cannot be derived from a public key.
const hardenedOffset uint32 = 0x8000_0000

// ErrInvalidChild is returned for the (cryptographically negligible) cases
// BIP32 defines as invalid: IL ≥ n, IL = 0, or a resulting point at infinity.
// Callers should skip to the next index.
var ErrInvalidChild = errors.New("invalid child key (IL ≥ n or point at infinity); try the next index")

// ErrHardenedFromPublic is returned when hardened derivation is attempted from
// a public key, which is impossible by design.
var ErrHardenedFromPublic = errors.New("cannot derive a hardened child from a public key")

// ExtendedPubKey is a parsed BIP32 extended public key (xpub).
type ExtendedPubKey struct {
	Version   [4]byte
	Depth     byte
	ChildNum  uint32
	ChainCode []byte // 32 bytes
	PubKey    []byte // 33-byte compressed secp256k1 point
}

// ParseExtendedPubKey decodes a Base58Check-encoded BIP32 extended PUBLIC key.
//
// It reuses the chain's audited Base58Check decoder (double-SHA256 checksum)
// and rejects extended PRIVATE keys (xprv) so secret material can never be
// loaded through this path. The 4-byte version prefix is accepted as-is, so a
// fork's custom xpub prefix works without special-casing.
func ParseExtendedPubKey(s string) (*ExtendedPubKey, error) {
	// Base58CheckDecode validates the 4-byte checksum and returns
	// (firstByte, remainingPayload); reassemble the full 78-byte body.
	first, rest, err := crypto.Base58CheckDecode(s)
	if err != nil {
		return nil, fmt.Errorf("decode extended key: %w", err)
	}
	body := make([]byte, 0, 1+len(rest))
	body = append(body, first)
	body = append(body, rest...)
	if len(body) != 78 {
		return nil, fmt.Errorf("extended key: expected 78-byte body, got %d", len(body))
	}

	key := body[45:78] // 33 bytes
	switch key[0] {
	case 0x02, 0x03:
		// compressed public key — expected
	case 0x00:
		return nil, errors.New("extended key is PRIVATE (xprv); only public keys (xpub) are accepted by the signer")
	default:
		return nil, fmt.Errorf("extended key: unexpected key prefix 0x%02x", key[0])
	}

	// Reject anything not a valid on-curve compressed point.
	if _, err := secp256k1.ParsePubKey(key); err != nil {
		return nil, fmt.Errorf("extended key: invalid public key: %w", err)
	}

	xpub := &ExtendedPubKey{
		Depth:     body[4],
		ChildNum:  binary.BigEndian.Uint32(body[9:13]),
		ChainCode: append([]byte(nil), body[13:45]...),
		PubKey:    append([]byte(nil), key...),
	}
	copy(xpub.Version[:], body[0:4])
	return xpub, nil
}

// Child derives the non-hardened child public key at index (BIP32 CKDpub):
//
//	I       = HMAC-SHA512(Key = cc_par, Data = serP(K_par) || ser32(i))
//	K_child = point(IL) + K_par   (i.e. IL·G + K_par)
//	cc_child= IR
func (k *ExtendedPubKey) Child(index uint32) (*ExtendedPubKey, error) {
	if index >= hardenedOffset {
		return nil, fmt.Errorf("%w: index %d", ErrHardenedFromPublic, index)
	}

	data := make([]byte, 37)
	copy(data[0:33], k.PubKey)
	binary.BigEndian.PutUint32(data[33:37], index)

	mac := hmac.New(sha512.New, k.ChainCode)
	mac.Write(data)
	sum := mac.Sum(nil)
	il, ir := sum[0:32], sum[32:64]

	var ilScalar secp256k1.ModNScalar
	if overflow := ilScalar.SetByteSlice(il); overflow || ilScalar.IsZero() {
		return nil, ErrInvalidChild // IL ≥ n or IL = 0
	}

	// childPoint = IL·G + parentPoint
	var ilG secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&ilScalar, &ilG)

	parent, err := secp256k1.ParsePubKey(k.PubKey)
	if err != nil {
		return nil, fmt.Errorf("parse parent pubkey: %w", err)
	}
	var parentJ secp256k1.JacobianPoint
	parent.AsJacobian(&parentJ)

	var childJ secp256k1.JacobianPoint
	secp256k1.AddNonConst(&ilG, &parentJ, &childJ)
	if childJ.Z.IsZero() {
		return nil, ErrInvalidChild // point at infinity
	}
	childJ.ToAffine()
	childPub := secp256k1.NewPublicKey(&childJ.X, &childJ.Y).SerializeCompressed()

	child := &ExtendedPubKey{
		Version:   k.Version,
		Depth:     k.Depth + 1,
		ChildNum:  index,
		ChainCode: append([]byte(nil), ir...),
		PubKey:    childPub,
	}
	return child, nil
}

// DerivePath applies a sequence of non-hardened child indices in order.
func (k *ExtendedPubKey) DerivePath(path ...uint32) (*ExtendedPubKey, error) {
	cur := k
	for _, idx := range path {
		next, err := cur.Child(idx)
		if err != nil {
			return nil, err
		}
		cur = next
	}
	return cur, nil
}
