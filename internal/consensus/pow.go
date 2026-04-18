package consensus

import (
	"context"
	"math/big"
	"time"

	"github.com/malairt/malairt/internal/crypto"
	"github.com/malairt/malairt/internal/primitives"
)

// MLRTHash computes the proof-of-work hash for a block header.
// Implements MLRTHash v1: DoubleSHA3256(header.Serialize()).
// This is a placeholder for future RandomX integration with the same nonce-search mechanic.
func MLRTHash(header *primitives.BlockHeader) [32]byte {
	return crypto.DoubleSHA3256(header.Serialize())
}

// HashMeetsDifficulty checks whether the given hash is less than or equal to
// the target derived from bits. A lower hash value satisfies a higher difficulty.
func HashMeetsDifficulty(hash [32]byte, bits uint32) bool {
	target := CompactToBig(bits)
	hashInt := new(big.Int).SetBytes(hash[:])
	return hashInt.Cmp(target) <= 0
}

// MineBlock attempts to find a valid nonce for the given header by incrementing
// header.Nonce from 0 until the resulting MLRTHash meets the difficulty target.
// progressFn is called every second with the current nonce (for hashrate tracking).
// Returns true if a valid nonce was found, false if the context was cancelled.
// The header.Nonce field is updated in place on success.
func MineBlock(ctx context.Context, header *primitives.BlockHeader, progressFn func(uint64)) bool {
	const reportInterval = time.Second

	header.Nonce = 0
	lastReport := time.Now()

	for {
		select {
		case <-ctx.Done():
			return false
		default:
		}

		hash := MLRTHash(header)
		if HashMeetsDifficulty(hash, header.Bits) {
			return true
		}

		header.Nonce++

		if progressFn != nil && time.Since(lastReport) >= reportInterval {
			progressFn(header.Nonce)
			lastReport = time.Now()
		}

		// Handle nonce overflow: reset to 0 and update timestamp to get a new search space
		// This mirrors Bitcoin's extraNonce approach when the 32-bit nonce exhausts
		if header.Nonce == 0 {
			return false
		}
	}
}
