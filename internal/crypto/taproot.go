package crypto

import (
	"errors"
	"fmt"

	btcec "github.com/btcsuite/btcd/btcec/v2"
	btcschnorr "github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// BIP-341 key tweaking.
//
// A taproot output does not commit directly to the wallet's internal key P;
// it commits to a tweaked key Q = P + t·G, where
//   t = int(tagged_hash("TapTweak", bytes(P) || merkle_root)) mod n
// and merkle_root is the root of the optional tapscript tree (empty when the
// wallet wants key-path-only spending). Committing via a tweak yields three
// properties consensus actually cares about:
//
//   - Indistinguishability: a pure key-path P2TR output looks identical
//     on-chain to a P2TR output that *could* have used tapscript but happened
//     not to. Observers can't tell whether a tree was ever committed.
//
//   - Unbreakable script-path commitment: nobody can invent a tapscript tree
//     that hashes to the same merkle root, because t is BIP-340 tagged.
//
//   - Correct signing: a signer who didn't know the tweak could produce
//     signatures valid under P but not under Q. The tweak math is
//     standardised so wallets match validators.

// TapTweakPubKey applies BIP-341's public-key tweak to a 32-byte x-only
// internal key. Returns the 32-byte x-only output key and the parity of the
// resulting point's y coordinate (true = odd).
//
// merkleRoot may be nil for key-path-only taproot (no script tree). When
// non-nil it must be 32 bytes — BIP-341's merkle root is a tagged-hash of the
// tapscript leaves.
func TapTweakPubKey(internalKey []byte, merkleRoot []byte) (xonly []byte, oddY bool, err error) {
	if len(internalKey) != 32 {
		return nil, false, errors.New("TapTweakPubKey: internalKey must be 32 bytes")
	}
	if merkleRoot != nil && len(merkleRoot) != 32 {
		return nil, false, fmt.Errorf("TapTweakPubKey: merkleRoot must be 32 bytes, got %d", len(merkleRoot))
	}

	// lift_x: schnorr.ParsePubKey accepts 32-byte x-only and returns the
	// unique point with even y.
	P, err := btcschnorr.ParsePubKey(internalKey)
	if err != nil {
		return nil, false, fmt.Errorf("TapTweakPubKey: lift_x failed: %w", err)
	}

	// Compute tweak scalar t.
	t, err := tapTweakScalar(internalKey, merkleRoot)
	if err != nil {
		return nil, false, err
	}

	// Q = P + t·G
	var tG, Pj, Q btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(t, &tG)
	P.AsJacobian(&Pj)
	btcec.AddNonConst(&Pj, &tG, &Q)
	Q.ToAffine()

	out := make([]byte, 32)
	Q.X.PutBytesUnchecked(out)
	return out, Q.Y.IsOdd(), nil
}

// TapTweakSecKey applies BIP-341's secret-key tweak. The returned 32-byte
// scalar, when used as a Schnorr signing key, produces signatures that verify
// under the output key returned by TapTweakPubKey(internalPubkey, merkleRoot)
// where internalPubkey is derived from secKey.
//
// BIP-341 mandates negating d whenever its derived public key has odd y
// (i.e. whenever lift_x of the pubkey differs from the raw point), since
// Schnorr verification operates on the even-y representative.
func TapTweakSecKey(secKey []byte, merkleRoot []byte) ([]byte, error) {
	if len(secKey) != 32 {
		return nil, errors.New("TapTweakSecKey: secKey must be 32 bytes")
	}
	if merkleRoot != nil && len(merkleRoot) != 32 {
		return nil, fmt.Errorf("TapTweakSecKey: merkleRoot must be 32 bytes, got %d", len(merkleRoot))
	}

	priv, _ := btcec.PrivKeyFromBytes(secKey)
	compressed := priv.PubKey().SerializeCompressed() // 33 bytes: 0x02/0x03 || x
	xOnly := compressed[1:]

	// Load d and conditionally negate when P has odd y.
	var d btcec.ModNScalar
	var dBytes [32]byte
	copy(dBytes[:], secKey)
	if overflow := d.SetBytes(&dBytes); overflow != 0 {
		return nil, errors.New("TapTweakSecKey: secKey overflows curve order")
	}
	if compressed[0] == 0x03 {
		d.Negate()
	}

	// d' = d_normalized + t  (mod n)
	t, err := tapTweakScalar(xOnly, merkleRoot)
	if err != nil {
		return nil, err
	}
	d.Add(t)

	out := d.Bytes()
	return out[:], nil
}

// TapLeafVersion is the default leaf version for tapscript (BIP-342). Other
// values are reserved for future soft-fork-activated script versions.
const TapLeafVersion byte = 0xc0

// TapLeafHash returns the BIP-342 leaf hash:
//   tagged_hash("TapLeaf", leafVersion || compactSize(len(script)) || script)
// The leaf version must have its low bit clear (0xc0 is the standard value).
func TapLeafHash(leafVersion byte, script []byte) [32]byte {
	buf := make([]byte, 0, 1+9+len(script))
	buf = append(buf, leafVersion)
	buf = append(buf, encodeCompactSize(uint64(len(script)))...)
	buf = append(buf, script...)
	return TaggedHash("TapLeaf", buf)
}

// TapBranchHash combines two merkle children per BIP-341: the two 32-byte
// inputs are placed in lexicographic order and hashed under the "TapBranch"
// tag. This lex ordering means the tree is a canonical merkle: no preimage
// of the root depends on which child was "left" vs "right".
func TapBranchHash(a, b [32]byte) [32]byte {
	lo, hi := a, b
	if bytesLess(hi[:], lo[:]) {
		lo, hi = b, a
	}
	buf := make([]byte, 64)
	copy(buf[:32], lo[:])
	copy(buf[32:], hi[:])
	return TaggedHash("TapBranch", buf)
}

// bytesLess reports whether a is lexicographically less than b.
func bytesLess(a, b []byte) bool {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

// encodeCompactSize encodes a uint64 as a Bitcoin-style "compact size" varint.
// Duplicated here to avoid a crypto→primitives dependency.
func encodeCompactSize(v uint64) []byte {
	switch {
	case v < 0xFD:
		return []byte{byte(v)}
	case v <= 0xFFFF:
		return []byte{0xFD, byte(v), byte(v >> 8)}
	case v <= 0xFFFFFFFF:
		return []byte{0xFE, byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
	default:
		return []byte{0xFF,
			byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24),
			byte(v >> 32), byte(v >> 40), byte(v >> 48), byte(v >> 56),
		}
	}
}

// tapTweakScalar returns the tagged-hash tweak scalar t as a *ModNScalar.
func tapTweakScalar(internalKeyXOnly []byte, merkleRoot []byte) (*btcec.ModNScalar, error) {
	hashInput := make([]byte, 0, 64)
	hashInput = append(hashInput, internalKeyXOnly...)
	hashInput = append(hashInput, merkleRoot...)
	h := TaggedHash("TapTweak", hashInput)
	var t btcec.ModNScalar
	if overflow := t.SetBytes(&h); overflow != 0 {
		return nil, errors.New("taptweak: hash ≥ curve order (retry with different merkle root)")
	}
	if t.IsZero() {
		return nil, errors.New("taptweak: hash is zero")
	}
	return &t, nil
}
