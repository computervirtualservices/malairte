package consensus

import (
	"math/big"
	"testing"
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
