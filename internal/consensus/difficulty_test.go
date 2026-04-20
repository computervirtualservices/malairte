package consensus

import (
	"math/big"
	"testing"

	"github.com/computervirtualservices/malairte/internal/primitives"
)

func TestCompactToBig(t *testing.T) {
	tests := []struct {
		bits     uint32
		expected string
	}{
		{
			bits:     0x207fffff,
			expected: "7fffff0000000000000000000000000000000000000000000000000000000000",
		},
		{
			bits:     0x1d00ffff, // Bitcoin mainnet genesis difficulty
			expected: "00000000ffff0000000000000000000000000000000000000000000000000000",
		},
		{
			bits:     0x03000000, // near-minimum target
			expected: "000000",
		},
	}

	for _, tc := range tests {
		got := CompactToBig(tc.bits)
		gotHex := got.Text(16)
		// Pad to expected length for zero-prefixed values
		if gotHex != tc.expected {
			// Accept if values are equal despite different zero padding
			expectedInt, _ := new(big.Int).SetString(tc.expected, 16)
			if got.Cmp(expectedInt) != 0 {
				t.Errorf("CompactToBig(0x%08x): got %s, want %s", tc.bits, gotHex, tc.expected)
			}
		}
	}
}

func TestBigToCompact(t *testing.T) {
	// Round-trip test: CompactToBig(BigToCompact(x)) == x
	origBits := uint32(0x207fffff)
	target := CompactToBig(origBits)
	roundTrip := BigToCompact(target)
	// Recompute target from round-tripped bits
	reTarget := CompactToBig(roundTrip)
	if target.Cmp(reTarget) != 0 {
		t.Errorf("BigToCompact round trip failed: %x -> %x -> %s (wanted %s)",
			origBits, roundTrip, reTarget.Text(16), target.Text(16))
	}
}

func TestCompactBigRoundTrip(t *testing.T) {
	bits := []uint32{
		0x207fffff,
		0x1d00ffff,
		0x1b0404cb,
		0x170a8034,
		0x1903e594,
	}
	for _, b := range bits {
		target := CompactToBig(b)
		if target.Sign() == 0 {
			continue
		}
		back := BigToCompact(target)
		target2 := CompactToBig(back)
		if target.Cmp(target2) != 0 {
			t.Errorf("Round trip mismatch for bits=0x%08x: %s != %s",
				b, target.Text(16), target2.Text(16))
		}
	}
}

func TestCalcNextRequiredDifficulty_NormalAdjustment(t *testing.T) {
	lastBits := uint32(0x207fffff)
	targetTime := int64(2016 * 120) // expected time for 2016 blocks at 120s each

	// If actual time == target time, difficulty should not change
	newBits := CalcNextRequiredDifficulty(lastBits, targetTime, targetTime)
	if newBits != lastBits {
		t.Errorf("No change expected when actual==target: got 0x%08x, want 0x%08x", newBits, lastBits)
	}
}

func TestCalcNextRequiredDifficulty_ClampUp(t *testing.T) {
	lastBits := uint32(0x207fffff)
	targetTime := int64(2016 * 120)

	// Very fast: actual time is 1/10 of target
	fastTime := targetTime / 10
	newBits := CalcNextRequiredDifficulty(lastBits, fastTime, targetTime)

	// New bits should represent a harder (smaller) target than lastBits,
	// but clamped to at most 4x harder
	oldTarget := CompactToBig(lastBits)
	newTarget := CompactToBig(newBits)

	// New target should be smaller than old target (harder)
	if newTarget.Cmp(oldTarget) > 0 {
		t.Errorf("Expected harder target (smaller value): old=%s new=%s",
			oldTarget.Text(16), newTarget.Text(16))
	}

	// New target should be at most 4x smaller.
	// Round-trip minTarget through compact representation before comparing:
	// BigToCompact truncates precision, so CompactToBig(BigToCompact(x)) <= x.
	// The algorithm and the final stored value both go through compact, so this
	// is the correct baseline for the comparison.
	minTarget := CompactToBig(BigToCompact(new(big.Int).Div(oldTarget, big.NewInt(4))))
	if newTarget.Cmp(minTarget) < 0 {
		t.Errorf("Difficulty increase clamping failed: target %s should not be below %s",
			newTarget.Text(16), minTarget.Text(16))
	}
}

func TestCalcNextRequiredDifficulty_ClampDown(t *testing.T) {
	lastBits := uint32(0x1d00ffff)
	targetTime := int64(2016 * 120)

	// Very slow: actual time is 100x target
	slowTime := targetTime * 100
	newBits := CalcNextRequiredDifficulty(lastBits, slowTime, targetTime)

	oldTarget := CompactToBig(lastBits)
	newTarget := CompactToBig(newBits)

	// New target should be larger (easier), but clamped to at most 4x larger
	if newTarget.Cmp(oldTarget) < 0 {
		t.Errorf("Expected easier target (larger value): old=%s new=%s",
			oldTarget.Text(16), newTarget.Text(16))
	}

	// New target should be at most 4x larger
	maxTarget := new(big.Int).Mul(oldTarget, big.NewInt(4))
	if newTarget.Cmp(maxTarget) > 0 {
		t.Errorf("Difficulty decrease clamping failed: target %s should not exceed %s",
			newTarget.Text(16), maxTarget.Text(16))
	}
}

func TestCalcNextRequiredDifficulty_MaxTarget(t *testing.T) {
	// At maximum (lowest difficulty), target should not increase further
	lastBits := uint32(0x207fffff)
	targetTime := int64(2016 * 120)
	slowTime := targetTime * 10 // much slower than target

	newBits := CalcNextRequiredDifficulty(lastBits, slowTime, targetTime)
	newTarget := CompactToBig(newBits)
	maxTarget := CompactToBig(maxBits)

	if newTarget.Cmp(maxTarget) > 0 {
		t.Errorf("Target %s exceeds max target %s", newTarget.Text(16), maxTarget.Text(16))
	}
}

// buildLWMAWindow builds LWMAWindow+1 consecutive headers spaced by solvetime
// seconds with constant bits, starting at startTime.
func buildLWMAWindow(startTime, solvetime int64, bits uint32) []*primitives.BlockHeader {
	hdrs := make([]*primitives.BlockHeader, LWMAWindow+1)
	for i := range hdrs {
		hdrs[i] = &primitives.BlockHeader{
			Height:    uint64(i),
			Timestamp: startTime + int64(i)*solvetime,
			Bits:      bits,
		}
	}
	return hdrs
}

func TestNextRequiredBitsLWMA_StableAtTarget(t *testing.T) {
	const T = int64(120)
	bits := uint32(0x1d00ffff)
	hdrs := buildLWMAWindow(1_000_000, T, bits) // solvetime == target
	got := NextRequiredBitsLWMA(hdrs, T, 0x1e0ffff0)

	oldTarget := CompactToBig(bits)
	newTarget := CompactToBig(got)

	// Round-trip tolerance: allow up to 2 ULP in compact space.
	diff := new(big.Int).Sub(newTarget, oldTarget)
	diff.Abs(diff)
	tol := new(big.Int).Rsh(oldTarget, 20) // ~1e-6 of old target
	if diff.Cmp(tol) > 0 {
		t.Errorf("stable-at-target should not move bits much: old=%x new=%x", bits, got)
	}
}

func TestNextRequiredBitsLWMA_FastBlocksRaiseDifficulty(t *testing.T) {
	const T = int64(120)
	bits := uint32(0x1d00ffff)
	hdrs := buildLWMAWindow(1_000_000, T/10, bits) // 10× too fast
	got := NextRequiredBitsLWMA(hdrs, T, 0x1e0ffff0)

	oldTarget := CompactToBig(bits)
	newTarget := CompactToBig(got)
	if newTarget.Cmp(oldTarget) >= 0 {
		t.Errorf("fast blocks should lower target (raise difficulty): old=%s new=%s",
			oldTarget.Text(16), newTarget.Text(16))
	}
}

func TestNextRequiredBitsLWMA_SlowBlocksLowerDifficulty(t *testing.T) {
	const T = int64(120)
	bits := uint32(0x1b0404cb) // a "hard" target well below pow_limit
	hdrs := buildLWMAWindow(1_000_000, T*4, bits) // 4× too slow
	got := NextRequiredBitsLWMA(hdrs, T, 0x1e0ffff0)

	oldTarget := CompactToBig(bits)
	newTarget := CompactToBig(got)
	if newTarget.Cmp(oldTarget) <= 0 {
		t.Errorf("slow blocks should raise target (lower difficulty): old=%s new=%s",
			oldTarget.Text(16), newTarget.Text(16))
	}
}

func TestNextRequiredBitsLWMA_ClampsAtPowLimit(t *testing.T) {
	const T = int64(120)
	powLimit := uint32(0x1e0ffff0)
	bits := uint32(0x1d00ffff)
	// Extremely slow — would push target above pow_limit if unclamped.
	hdrs := buildLWMAWindow(1_000_000, T*100, bits)
	got := NextRequiredBitsLWMA(hdrs, T, powLimit)

	newTarget := CompactToBig(got)
	limitTarget := CompactToBig(powLimit)
	if newTarget.Cmp(limitTarget) > 0 {
		t.Errorf("target %s exceeds pow_limit %s", newTarget.Text(16), limitTarget.Text(16))
	}
}

func TestNextRequiredBitsLWMA_ShortWindowReturnsPowLimit(t *testing.T) {
	const T = int64(120)
	powLimit := uint32(0x1e0ffff0)
	hdrs := buildLWMAWindow(1_000_000, T, 0x1d00ffff)[:5] // too few
	got := NextRequiredBitsLWMA(hdrs, T, powLimit)
	if got != powLimit {
		t.Errorf("short window should fall back to pow_limit: got %08x want %08x", got, powLimit)
	}
}

func TestNextRequiredBitsLWMA_ResistsNegativeTimestampSpike(t *testing.T) {
	const T = int64(120)
	bits := uint32(0x1d00ffff)
	hdrs := buildLWMAWindow(1_000_000, T, bits)
	// Inject a pathological timestamp: block N jumps 1 hour backwards.
	hdrs[LWMAWindow].Timestamp = hdrs[LWMAWindow-1].Timestamp - 3600

	got := NextRequiredBitsLWMA(hdrs, T, 0x1e0ffff0)
	// Should not produce an absurd result: target must remain within ~4× of original.
	oldT := CompactToBig(bits)
	newT := CompactToBig(got)
	maxMove := new(big.Int).Mul(oldT, big.NewInt(4))
	minMove := new(big.Int).Quo(oldT, big.NewInt(4))
	if newT.Cmp(maxMove) > 0 || newT.Cmp(minMove) < 0 {
		t.Errorf("negative-timestamp spike produced extreme target: old=%s new=%s",
			oldT.Text(16), newT.Text(16))
	}
}

func TestCalcMedianTimePast(t *testing.T) {
	mk := func(ts ...int64) []*primitives.BlockHeader {
		h := make([]*primitives.BlockHeader, len(ts))
		for i, t := range ts {
			h[i] = &primitives.BlockHeader{Timestamp: t}
		}
		return h
	}
	// Fewer than 11 headers: median of all.
	if got := CalcMedianTimePast(mk(10, 20, 30)); got != 20 {
		t.Errorf("median of 3: got %d want 20", got)
	}
	// 11 headers — median is the 6th element (index 5) after sort.
	got := CalcMedianTimePast(mk(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11))
	if got != 6 {
		t.Errorf("median of 11 sorted: got %d want 6", got)
	}
	// More than 11 headers: only last 11 matter.
	got = CalcMedianTimePast(mk(999, 999, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11))
	if got != 6 {
		t.Errorf("median of last 11: got %d want 6", got)
	}
	// Out-of-order timestamps (an attacker-controlled block) still produce
	// the true median.
	got = CalcMedianTimePast(mk(100, 50, 200, 25, 175, 10, 150, 5, 125, 1, 110))
	// sorted: 1,5,10,25,50,100,110,125,150,175,200 → median = 100
	if got != 100 {
		t.Errorf("median of unsorted: got %d want 100", got)
	}
	// Empty.
	if got := CalcMedianTimePast(nil); got != 0 {
		t.Errorf("empty: got %d want 0", got)
	}
}
