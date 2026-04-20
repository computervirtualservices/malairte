// Package consensus implements the Malairt proof-of-work and difficulty adjustment logic.
package consensus

import (
	"math/big"

	"github.com/computervirtualservices/malairte/internal/primitives"
)

// InitialBits is the genesis block difficulty target in compact format.
// 0x207fffff is a very easy target (same as Bitcoin testnet genesis),
// allowing devnet blocks to be found instantly with nonce=0.
const InitialBits uint32 = 0x207fffff

// maxBits is the maximum allowed compact target (lowest difficulty).
const maxBits uint32 = 0x207fffff

// minBits is the minimum allowed compact target (highest difficulty).
// Prevents the difficulty from becoming impossibly hard.
const minBits uint32 = 0x03000000

// LWMA window and clamp constants per Malairt Consensus Spec v1 §3.
// Window N is the number of previous blocks considered by the LWMA retarget.
// Solvetime clamp bounds prevent a single bad timestamp (or time-warp attack)
// from dominating the weighted mean.
const (
	LWMAWindow            = 60
	LWMASolvetimeLowMult  = -5 // min solvetime = -5 * T (T = target block time)
	LWMASolvetimeHighMult = 6  // max solvetime =  6 * T
)

// CompactToBig converts a compact "bits" representation to a *big.Int target.
// The compact format is: bits = (exponent << 24) | (mantissa & 0x7fffff).
// target = mantissa * 2^(8*(exponent-3))
func CompactToBig(bits uint32) *big.Int {
	// Extract mantissa (lower 23 bits) and exponent (upper 8 bits)
	mantissa := bits & 0x007fffff
	exponent := uint(bits >> 24)
	isNegative := bits&0x00800000 != 0

	var target *big.Int
	if exponent <= 3 {
		mantissa >>= 8 * (3 - exponent)
		target = big.NewInt(int64(mantissa))
	} else {
		target = big.NewInt(int64(mantissa))
		target.Lsh(target, 8*(exponent-3))
	}

	if isNegative {
		target.Neg(target)
	}

	return target
}

// BigToCompact converts a *big.Int target back to the compact bits representation.
// Returns the compact encoding of the target.
func BigToCompact(target *big.Int) uint32 {
	if target.Sign() == 0 {
		return 0
	}

	isNegative := target.Sign() < 0
	absTarget := new(big.Int).Abs(target)

	// Find the byte length needed
	byteLen := uint(len(absTarget.Bytes()))
	var mantissa uint32
	if byteLen <= 3 {
		mantissa = uint32(absTarget.Int64()) << (8 * (3 - byteLen))
	} else {
		// Shift right to fit in 3 bytes
		shifted := new(big.Int).Rsh(absTarget, 8*(byteLen-3))
		mantissa = uint32(shifted.Int64())
	}

	// If the sign bit is set in the mantissa, bump the exponent
	if mantissa&0x00800000 != 0 {
		mantissa >>= 8
		byteLen++
	}

	compact := (byteLen << 24) | uint(mantissa&0x007fffff)
	if isNegative {
		compact |= 0x00800000
	}
	return uint32(compact)
}

// CalcNextRequiredDifficulty calculates the next difficulty target after a retarget window.
// It uses the same algorithm as Bitcoin, clamped to 4x up/down per window.
//
// lastBits: the compact bits target of the last block in the window.
// actualTime: the actual time elapsed in seconds for the retarget window.
// targetTime: the expected time in seconds (RetargetInterval * BlockTime).
// Returns the new compact bits, clamped so difficulty cannot change more than 4x.
func CalcNextRequiredDifficulty(lastBits uint32, actualTime int64, targetTime int64) uint32 {
	// Clamp actual time to prevent extreme adjustments
	minTime := targetTime / 4
	maxTime := targetTime * 4

	if actualTime < minTime {
		actualTime = minTime
	}
	if actualTime > maxTime {
		actualTime = maxTime
	}

	// new_target = old_target * actual_time / target_time
	oldTarget := CompactToBig(lastBits)
	newTarget := new(big.Int).Mul(oldTarget, big.NewInt(actualTime))
	newTarget.Div(newTarget, big.NewInt(targetTime))

	// Clamp to maximum (minimum difficulty)
	maxTarget := CompactToBig(maxBits)
	if newTarget.Cmp(maxTarget) > 0 {
		newTarget.Set(maxTarget)
	}

	// Clamp to minimum (maximum difficulty), only if minBits target is smaller (harder)
	minTarget := CompactToBig(minBits)
	if newTarget.Cmp(minTarget) < 0 {
		newTarget.Set(minTarget)
	}

	return BigToCompact(newTarget)
}

// NextRequiredBitsLWMA computes the next block's compact difficulty target using
// LWMA-1 (Zawy's Linearly Weighted Moving Average) over a rolling window of the
// previous LWMAWindow blocks. It retargets every block — no 2016-block window,
// no 4× clamp — allowing fast response to hashrate changes.
//
// window must contain exactly LWMAWindow+1 consecutive headers ending at the
// parent of the block being mined. window[0] is only used as the timestamp
// anchor for the first solvetime. If len(window) < LWMAWindow+1 the caller
// should fall back to powLimitBits (this function returns powLimitBits in that
// case rather than panicking, so callers can safely pass short slices during
// the first LWMAWindow blocks).
//
// blockTime is the target block time in seconds (e.g. 120 for Malairt).
// powLimitBits is the easiest permitted target (compact form) — results are
// clamped to never exceed it.
//
// Solvetimes are clamped per-entry to [LWMASolvetimeLowMult*T, LWMASolvetimeHighMult*T]
// before contributing to the weighted sum, which neutralises single-block
// timestamp manipulation. The final sum is also floored at 1 to prevent
// division-by-zero when the window is suspiciously fast.
func NextRequiredBitsLWMA(window []*primitives.BlockHeader, blockTime int64, powLimitBits uint32) uint32 {
	const N = LWMAWindow
	if len(window) < N+1 || blockTime <= 0 {
		return powLimitBits
	}
	// Use only the last N+1 headers (caller may pass more).
	w := window[len(window)-(N+1):]

	T := blockTime
	minST := int64(LWMASolvetimeLowMult) * T
	maxST := int64(LWMASolvetimeHighMult) * T

	var sumWeightedST int64
	sumTargets := new(big.Int)

	for i := 1; i <= N; i++ {
		st := w[i].Timestamp - w[i-1].Timestamp
		if st < minST {
			st = minST
		}
		if st > maxST {
			st = maxST
		}
		sumWeightedST += int64(i) * st
		sumTargets.Add(sumTargets, CompactToBig(w[i].Bits))
	}

	// Floor to avoid tiny/negative denominators during extreme timestamp spoofing.
	// N*(N+1)/2 * T / 4 is the denominator that would result if every solvetime
	// were T/4 — the fastest "normal" window we want to allow to influence bits.
	minDenom := int64(N*(N+1)/2) * T / 4
	if sumWeightedST < minDenom {
		sumWeightedST = minDenom
	}

	// nextTarget = avgTarget * sumWeightedST / (T * N*(N+1)/2)
	denom := big.NewInt(int64(N*(N+1)/2) * T)
	avg := new(big.Int).Quo(sumTargets, big.NewInt(int64(N)))
	next := new(big.Int).Mul(avg, big.NewInt(sumWeightedST))
	next.Quo(next, denom)

	powLimit := CompactToBig(powLimitBits)
	if next.Sign() <= 0 {
		return powLimitBits
	}
	if next.Cmp(powLimit) > 0 {
		next.Set(powLimit)
	}
	return BigToCompact(next)
}

// CalcMedianTimePast returns the median of the last up-to-11 block timestamps
// ending at headers[len(headers)-1]. The median-time-past (MTP) is used as the
// lower bound for a new block's timestamp, which prevents single-block
// timestamp regression attacks while still tolerating small clock skew.
//
// If headers is empty, returns 0.
func CalcMedianTimePast(headers []*primitives.BlockHeader) int64 {
	const windowLen = 11
	if len(headers) == 0 {
		return 0
	}
	start := len(headers) - windowLen
	if start < 0 {
		start = 0
	}
	w := headers[start:]
	ts := make([]int64, len(w))
	for i, h := range w {
		ts[i] = h.Timestamp
	}
	// Insertion sort — window is ≤11.
	for i := 1; i < len(ts); i++ {
		for j := i; j > 0 && ts[j-1] > ts[j]; j-- {
			ts[j-1], ts[j] = ts[j], ts[j-1]
		}
	}
	return ts[len(ts)/2]
}
