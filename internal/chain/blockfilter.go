package chain

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sort"

	"github.com/computervirtualservices/malairte/internal/primitives"
)

// Compact block filters — BIP-158 basic variant.
//
// A block filter is a compact probabilistic set that lets a light client ask
// "does this block contain outputs paying, or inputs spending, any of my
// addresses?" without downloading the block itself. Each filter is a
// Golomb-coded set (GCS) over SipHash-2-4 digests of:
//
//   - every output's scriptPubKey in the block's transactions, AND
//   - every spent input's previously-committed scriptPubKey (prevout script).
//
// Inputs (the second category) let a client detect when its own coins were
// spent — the scriptPubKey of a UTXO it owned appears in the filter when that
// UTXO is consumed. Because the prevout scripts are destroyed by the block's
// Apply, the node builds and persists the filter BEFORE applying, passing
// the resolved spent scripts in alongside the block.

// GCS parameters match BIP-158.
const (
	filterBitsP uint8  = 19
	filterM     uint64 = 784931
)

// BuildBlockFilter returns the compact block filter for the block. spentScripts
// is the vector of scriptPubKeys being spent, one entry per non-coinbase input
// in input order. Callers resolve these from the UTXO set BEFORE
// UTXOSet.Apply consumes the outputs; passing nil produces an output-only
// filter (a legal but weaker form).
//
// Deterministic: same block + same spentScripts → same bytes.
//
// Filter format (BIP-158 wire):
//   varint(N)            // number of elements
//   gcs_encoded_set(...)  // GCS-coded sorted differences
func BuildBlockFilter(block *primitives.Block, spentScripts [][]byte) []byte {
	// 1. Collect distinct scriptPubKeys from outputs AND spent inputs.
	var scripts [][]byte
	seen := make(map[string]struct{})
	addScript := func(s []byte) {
		if len(s) == 0 {
			return
		}
		key := string(s)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		scripts = append(scripts, s)
	}
	for _, tx := range block.Txs {
		for _, out := range tx.Outputs {
			addScript(out.ScriptPubKey)
		}
	}
	for _, s := range spentScripts {
		addScript(s)
	}
	if len(scripts) == 0 {
		// Empty filter: single varint(0).
		return []byte{0x00}
	}

	// 2. Hash each to a 64-bit value via keyed siphash, then map into
	//    [0, N*M) via the BIP-158 "map to value range" step.
	key := FilterKey(block.Header.Hash())
	N := uint64(len(scripts))
	F := N * filterM
	values := make([]uint64, 0, N)
	for _, s := range scripts {
		h := siphash24(key, s)
		// Map via multiply-and-shift (no modulo bias in practice given 64-bit widening).
		v := mulShift64(h, F)
		values = append(values, v)
	}

	// 3. Sort ascending so we can encode differences.
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })

	// 4. Deduplicate — BIP-158 specifies this; differences of zero would
	//    encode as "quotient 0, remainder 0" which collides with real 0s.
	dedup := values[:1]
	for _, v := range values[1:] {
		if v != dedup[len(dedup)-1] {
			dedup = append(dedup, v)
		}
	}

	// 5. Emit: varint(len) + GCS(differences).
	out := primitives.EncodeVarIntPub(uint64(len(dedup)))
	w := &bitWriter{}
	prev := uint64(0)
	for _, v := range dedup {
		d := v - prev
		prev = v
		encodeGolombRice(w, d, filterBitsP)
	}
	return append(out, w.Bytes()...)
}

// FilterHash returns SHA256(filter) — the commitment a BIP-157 filter header
// references.
func FilterHash(filter []byte) [32]byte {
	return sha256.Sum256(filter)
}

// FilterHeader returns the BIP-157 header commitment for this block's
// filter, chained to the previous block's filter header:
//   header = SHA256( SHA256(filter) || prevHeader )
// Light clients keep a single up-to-date header and verify long runs of
// filters in O(1) time by replaying this recurrence from the last trusted
// header. prevHeader is the zero value for the genesis block.
func FilterHeader(filterHash, prevHeader [32]byte) [32]byte {
	var buf [64]byte
	copy(buf[:32], filterHash[:])
	copy(buf[32:], prevHeader[:])
	return sha256.Sum256(buf[:])
}

// FilterKey returns the 16-byte SipHash key derived from the first 16 bytes
// of the block hash. Deterministic per-block; lets anyone who knows the
// block hash verify the filter without further inputs.
func FilterKey(blockHash [32]byte) [16]byte {
	var k [16]byte
	copy(k[:], blockHash[:16])
	return k
}

// FilterMatchAny returns true if any of the given scriptPubKeys is present
// in filter (with the same probabilistic guarantees BIP-158 gives: no false
// negatives, false-positive rate 1/M per element).
func FilterMatchAny(filter []byte, key [16]byte, scripts [][]byte) (bool, error) {
	if len(filter) == 0 {
		return false, errors.New("filter is empty")
	}
	N64, consumed, err := primitives.DecodeVarInt(filter)
	if err != nil {
		return false, err
	}
	N := N64
	if N == 0 {
		return false, nil
	}
	body := filter[consumed:]

	F := N * filterM
	targets := make([]uint64, 0, len(scripts))
	for _, s := range scripts {
		targets = append(targets, mulShift64(siphash24(key, s), F))
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i] < targets[j] })

	r := &bitReader{buf: body}
	var cur uint64
	ti := 0
	for i := uint64(0); i < N && ti < len(targets); i++ {
		d, err := decodeGolombRice(r, filterBitsP)
		if err != nil {
			return false, err
		}
		cur += d
		// Advance targets past values smaller than the current filter entry.
		for ti < len(targets) && targets[ti] < cur {
			ti++
		}
		if ti < len(targets) && targets[ti] == cur {
			return true, nil
		}
	}
	return false, nil
}

// mulShift64 computes (a * b) >> 64 in constant time using Go's built-in
// 128-bit multiplication helper. This is BIP-158's suggested bias-free
// mapping from [0, 2^64) to [0, b).
func mulShift64(a, b uint64) uint64 {
	hi, _ := mulU64(a, b)
	return hi
}

// mulU64 returns the 128-bit product a*b split into (high64, low64).
func mulU64(a, b uint64) (hi, lo uint64) {
	const mask = uint64(1<<32) - 1
	aLo, aHi := a&mask, a>>32
	bLo, bHi := b&mask, b>>32
	lo = aLo * bLo
	mid1 := aHi * bLo
	mid2 := aLo * bHi
	midLo := (lo >> 32) + (mid1 & mask) + (mid2 & mask)
	lo = (midLo << 32) | (lo & mask)
	hi = aHi*bHi + (mid1 >> 32) + (mid2 >> 32) + (midLo >> 32)
	return
}

// ── Golomb-Rice coding ────────────────────────────────────────────────────────

// encodeGolombRice encodes one non-negative integer using Golomb-Rice with
// parameter P: the quotient (n >> P) is unary-coded followed by a 0 bit, and
// the remainder (n & ((1<<P)-1)) is written as P bits.
func encodeGolombRice(w *bitWriter, n uint64, P uint8) {
	q := n >> P
	for i := uint64(0); i < q; i++ {
		w.writeBit(1)
	}
	w.writeBit(0)
	rem := n & ((1 << P) - 1)
	w.writeBits(rem, int(P))
}

func decodeGolombRice(r *bitReader, P uint8) (uint64, error) {
	// Count 1 bits until a 0 bit — that's the quotient.
	var q uint64
	for {
		b, err := r.readBit()
		if err != nil {
			return 0, err
		}
		if b == 0 {
			break
		}
		q++
		if q > 1<<24 {
			return 0, errors.New("golomb-rice quotient too large")
		}
	}
	rem, err := r.readBits(int(P))
	if err != nil {
		return 0, err
	}
	return (q << P) | rem, nil
}

// ── Bit-level I/O ─────────────────────────────────────────────────────────────

type bitWriter struct {
	buf   []byte
	nbits int // number of bits written into the current tail byte
}

func (w *bitWriter) writeBit(b uint8) {
	if w.nbits == 0 {
		w.buf = append(w.buf, 0)
	}
	tail := &w.buf[len(w.buf)-1]
	// Bits are packed MSB-first within each byte (BIP-158 convention).
	*tail |= (b & 1) << (7 - w.nbits)
	w.nbits++
	if w.nbits == 8 {
		w.nbits = 0
	}
}

func (w *bitWriter) writeBits(v uint64, n int) {
	for i := n - 1; i >= 0; i-- {
		w.writeBit(uint8((v >> i) & 1))
	}
}

func (w *bitWriter) Bytes() []byte {
	return w.buf
}

type bitReader struct {
	buf   []byte
	pos   int // byte index
	nbits int // bits already consumed in buf[pos]
}

func (r *bitReader) readBit() (uint8, error) {
	if r.pos >= len(r.buf) {
		return 0, errors.New("bitReader: out of bits")
	}
	b := (r.buf[r.pos] >> (7 - r.nbits)) & 1
	r.nbits++
	if r.nbits == 8 {
		r.nbits = 0
		r.pos++
	}
	return b, nil
}

func (r *bitReader) readBits(n int) (uint64, error) {
	var v uint64
	for i := 0; i < n; i++ {
		b, err := r.readBit()
		if err != nil {
			return 0, err
		}
		v = (v << 1) | uint64(b)
	}
	return v, nil
}

// ── SipHash-2-4 ───────────────────────────────────────────────────────────────
//
// Minimal SipHash-2-4 implementation. We use the same constants and round
// schedule as the reference (2 compression rounds, 4 finalization rounds).

func siphash24(key [16]byte, m []byte) uint64 {
	k0 := binary.LittleEndian.Uint64(key[:8])
	k1 := binary.LittleEndian.Uint64(key[8:])

	v0 := k0 ^ 0x736f6d6570736575
	v1 := k1 ^ 0x646f72616e646f6d
	v2 := k0 ^ 0x6c7967656e657261
	v3 := k1 ^ 0x7465646279746573

	// Process 8-byte blocks.
	l := len(m)
	blocks := l / 8
	for i := 0; i < blocks; i++ {
		mi := binary.LittleEndian.Uint64(m[i*8 : i*8+8])
		v3 ^= mi
		v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
		v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
		v0 ^= mi
	}

	// Final block: last 0..7 bytes + length byte at position 7.
	var last [8]byte
	copy(last[:], m[blocks*8:])
	last[7] = byte(l & 0xff)
	mi := binary.LittleEndian.Uint64(last[:])
	v3 ^= mi
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	v0 ^= mi

	// Finalization: 4 rounds on v2 ^= 0xff.
	v2 ^= 0xff
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)

	return v0 ^ v1 ^ v2 ^ v3
}

func sipRound(v0, v1, v2, v3 uint64) (uint64, uint64, uint64, uint64) {
	v0 += v1
	v1 = (v1 << 13) | (v1 >> (64 - 13))
	v1 ^= v0
	v0 = (v0 << 32) | (v0 >> 32)
	v2 += v3
	v3 = (v3 << 16) | (v3 >> (64 - 16))
	v3 ^= v2
	v0 += v3
	v3 = (v3 << 21) | (v3 >> (64 - 21))
	v3 ^= v0
	v2 += v1
	v1 = (v1 << 17) | (v1 >> (64 - 17))
	v1 ^= v2
	v2 = (v2 << 32) | (v2 >> 32)
	return v0, v1, v2, v3
}
