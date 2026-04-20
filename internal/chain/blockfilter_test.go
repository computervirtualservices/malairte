package chain

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/computervirtualservices/malairte/internal/primitives"
)

// testBlock builds a tiny block with the given output scripts on a single tx.
func testBlock(t *testing.T, scripts [][]byte) *primitives.Block {
	t.Helper()
	outs := make([]primitives.TxOutput, len(scripts))
	for i, s := range scripts {
		outs[i] = primitives.TxOutput{Value: 1000, ScriptPubKey: s}
	}
	coinbase := primitives.NewCoinbaseTx(1, 50_000_000_000, scripts[0], 0)
	// Override the coinbase's default output with our test scripts by
	// attaching them as additional (fake) transactions. Simplest: use a
	// single non-coinbase tx with our outputs.
	spender := &primitives.Transaction{
		Version: 1,
		Inputs: []primitives.TxInput{{
			PreviousOutput: primitives.OutPoint{TxID: [32]byte{0x11}, Index: 0},
			Sequence:       0xFFFFFFFF,
		}},
		Outputs: outs,
	}
	return &primitives.Block{
		Header: primitives.BlockHeader{
			Version: 1, Timestamp: 1_700_000_000, Bits: 0x207fffff, Height: 1,
		},
		Txs: []*primitives.Transaction{coinbase, spender},
	}
}

func TestBlockFilter_DeterministicAndMatchesOutputs(t *testing.T) {
	// Build a block with three distinct output scripts.
	mine := bytes.Repeat([]byte{0xA1}, 22)
	other1 := bytes.Repeat([]byte{0xB2}, 22)
	other2 := bytes.Repeat([]byte{0xC3}, 22)
	block := testBlock(t, [][]byte{mine, other1, other2})

	// Determinism: two independent builds must produce identical bytes.
	f1 := BuildBlockFilter(block, nil)
	f2 := BuildBlockFilter(block, nil)
	if !bytes.Equal(f1, f2) {
		t.Fatalf("filter not deterministic:\n f1=%s\n f2=%s",
			hex.EncodeToString(f1), hex.EncodeToString(f2))
	}
	if len(f1) < 2 {
		t.Fatalf("filter too short: %s", hex.EncodeToString(f1))
	}

	// No false negatives: each output script must match.
	key := FilterKey(block.Header.Hash())
	for i, s := range [][]byte{mine, other1, other2} {
		ok, err := FilterMatchAny(f1, key, [][]byte{s})
		if err != nil {
			t.Fatalf("FilterMatchAny[%d]: %v", i, err)
		}
		if !ok {
			t.Errorf("output script %d must match filter", i)
		}
	}

	// A script NOT in the block should almost certainly miss. With only 3
	// elements and M=784931, the false-positive probability for one probe
	// is ~1/784931 × 3 — effectively zero for a single-run test.
	ok, err := FilterMatchAny(f1, key, [][]byte{bytes.Repeat([]byte{0xFF}, 22)})
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("unrelated script must not match (false-positive probability is effectively 0)")
	}
}

func TestBlockFilter_EmptyBlock(t *testing.T) {
	// A block whose only tx is a coinbase with an empty script produces an
	// empty filter (a single varint(0)).
	coinbase := &primitives.Transaction{
		Version: 1,
		Inputs: []primitives.TxInput{{
			PreviousOutput: primitives.OutPoint{TxID: [32]byte{}, Index: 0xFFFFFFFF},
			Sequence:       0xFFFFFFFF,
		}},
		Outputs: []primitives.TxOutput{{Value: 100, ScriptPubKey: nil}},
	}
	block := &primitives.Block{
		Header: primitives.BlockHeader{Version: 1, Height: 0},
		Txs:    []*primitives.Transaction{coinbase},
	}
	f := BuildBlockFilter(block, nil)
	if len(f) != 1 || f[0] != 0x00 {
		t.Errorf("empty filter: got %s, want 00", hex.EncodeToString(f))
	}
}

func TestSipHash_KnownVector(t *testing.T) {
	// SipHash-2-4 canonical test vector: key = 00 01 ... 0F, message = 00..0E.
	// Expected output: 0xa129ca6149be45e5 (from the SipHash reference).
	var key [16]byte
	for i := range key {
		key[i] = byte(i)
	}
	msg := make([]byte, 15)
	for i := range msg {
		msg[i] = byte(i)
	}
	got := siphash24(key, msg)
	const want uint64 = 0xa129ca6149be45e5
	if got != want {
		t.Errorf("siphash: got %016x, want %016x", got, want)
	}
}

func TestFilterHeader_ChainProperty(t *testing.T) {
	// FilterHeader must form a hash chain: changing any link invalidates
	// every header after it. Verifies light-client chain-of-commitments is
	// well-formed.
	filter0 := []byte{0x00}
	filter1 := []byte{0x01, 0xAB}
	filter2 := []byte{0x01, 0xCD}

	// Genesis: prev = zeros.
	var zero [32]byte
	h0 := FilterHeader(FilterHash(filter0), zero)
	h1 := FilterHeader(FilterHash(filter1), h0)
	h2 := FilterHeader(FilterHash(filter2), h1)

	// Deterministic.
	if h0 != FilterHeader(FilterHash(filter0), zero) {
		t.Error("FilterHeader must be deterministic")
	}

	// Changing the genesis filter propagates through every later header.
	filter0Prime := []byte{0x00, 0x99}
	h0Prime := FilterHeader(FilterHash(filter0Prime), zero)
	if h0 == h0Prime {
		t.Error("different genesis filter must produce different header")
	}
	h1Prime := FilterHeader(FilterHash(filter1), h0Prime)
	if h1 == h1Prime {
		t.Error("changed prev header must propagate to next header")
	}

	// The full chain stays distinct at every level.
	h2Prime := FilterHeader(FilterHash(filter2), h1Prime)
	if h2 == h2Prime {
		t.Error("chain of commitments must be hash-bound end-to-end")
	}
}

func TestGolombRice_RoundTrip(t *testing.T) {
	values := []uint64{0, 1, 2, 17, 1000, 12345, 999_999, 1 << 24}
	w := &bitWriter{}
	for _, v := range values {
		encodeGolombRice(w, v, 19)
	}
	r := &bitReader{buf: w.Bytes()}
	for i, v := range values {
		got, err := decodeGolombRice(r, 19)
		if err != nil {
			t.Fatalf("decode[%d]: %v", i, err)
		}
		if got != v {
			t.Errorf("value %d: got %d, want %d", i, got, v)
		}
	}
}
