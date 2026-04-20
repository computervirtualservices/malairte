// Package crypto provides cryptographic primitives for the Malairt blockchain.
package crypto

import (
	"crypto/sha256"

	"golang.org/x/crypto/ripemd160" //nolint:staticcheck // Required for Bitcoin-compatible Hash160
	"golang.org/x/crypto/sha3"
)

// SHA3256 returns the SHA3-256 digest of data.
func SHA3256(data []byte) [32]byte {
	h := sha3.New256()
	h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// DoubleSHA3256 returns SHA3-256(SHA3-256(data)) — used for block hashing (MLRTHash).
func DoubleSHA3256(data []byte) [32]byte {
	first := SHA3256(data)
	return SHA3256(first[:])
}

// Hash256 returns SHA256(SHA256(data)) — used for transaction hashing (Bitcoin-compatible).
func Hash256(data []byte) [32]byte {
	first := sha256.Sum256(data)
	return sha256.Sum256(first[:])
}

// TaggedHash computes the BIP-340/341/342 tagged hash used throughout the
// taproot stack:
//   tagged_hash(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)
// Every domain uses a distinct tag (e.g. "TapSighash", "TapTweak",
// "TapBranch", "TapLeaf") so that a hash produced for one purpose can never
// be confused with a valid hash of another purpose.
func TaggedHash(tag string, msg []byte) [32]byte {
	tagHash := sha256.Sum256([]byte(tag))
	h := sha256.New()
	h.Write(tagHash[:])
	h.Write(tagHash[:])
	h.Write(msg)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Hash160 returns RIPEMD160(SHA256(data)) — used for address derivation.
func Hash160(data []byte) [20]byte {
	h1 := sha256.Sum256(data)
	h2 := ripemd160.New()
	h2.Write(h1[:])
	var out [20]byte
	copy(out[:], h2.Sum(nil))
	return out
}
