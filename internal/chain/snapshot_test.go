package chain

import (
	"bytes"
	"testing"

	"github.com/computervirtualservices/malairte/internal/primitives"
)

func TestSnapshot_Deterministic(t *testing.T) {
	// A fresh chain with just the genesis UTXO set. Two snapshots must be
	// byte-identical — the sort order inside the serializer is what makes
	// this robust across DB implementations.
	params := new(ChainParams)
	*params = TestNetParams
	bc, err := NewBlockchain(params, newMemDB())
	if err != nil {
		t.Fatal(err)
	}

	s1, err := BuildSnapshot(bc)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := BuildSnapshot(bc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s1.Serialize(), s2.Serialize()) {
		t.Error("snapshots must be byte-identical for the same chain state")
	}
	if s1.Hash() != s2.Hash() {
		t.Error("snapshot hashes must match")
	}
}

func TestSnapshot_SerializeRoundTrip(t *testing.T) {
	// Construct a snapshot by hand with a known UTXO, serialize, deserialize,
	// assert equality. Exercises every field of the wire format.
	orig := &Snapshot{
		Height:    42,
		BlockHash: [32]byte{0xAA, 0xBB, 0xCC},
	}
	// Two UTXOs in deliberately non-sorted insertion order — the
	// serializer expects the caller to pre-sort. We'll compare via hash
	// after sorting to avoid depending on input order.
	u1 := &UTXO{
		TxID:   [32]byte{0x01},
		Index:  0,
		Value:  100_000,
		Script: []byte{0x51},
		Height: 10,
	}
	u2 := &UTXO{
		TxID:       [32]byte{0x02},
		Index:      3,
		Value:      999,
		Script:     []byte{0x76, 0xa9, 0x14},
		Height:     11,
		IsCoinbase: true,
	}
	orig.UTXOs = []*UTXO{u1, u2}

	raw := orig.Serialize()
	if string(raw[:4]) != "MLSN" {
		t.Errorf("magic: got %q, want MLSN", string(raw[:4]))
	}

	decoded, err := DeserializeSnapshot(raw)
	if err != nil {
		t.Fatalf("DeserializeSnapshot: %v", err)
	}
	if decoded.Height != orig.Height {
		t.Errorf("height: got %d, want %d", decoded.Height, orig.Height)
	}
	if decoded.BlockHash != orig.BlockHash {
		t.Errorf("blockHash mismatch")
	}
	if len(decoded.UTXOs) != 2 {
		t.Fatalf("utxo count: got %d, want 2", len(decoded.UTXOs))
	}
	// Field-by-field compare of UTXOs.
	for i, u := range orig.UTXOs {
		d := decoded.UTXOs[i]
		if u.TxID != d.TxID || u.Index != d.Index || u.Value != d.Value ||
			u.Height != d.Height || u.IsCoinbase != d.IsCoinbase ||
			!bytes.Equal(u.Script, d.Script) {
			t.Errorf("utxo %d mismatch: orig=%+v decoded=%+v", i, u, d)
		}
	}
}

func TestSnapshot_LoadWritesUTXOs(t *testing.T) {
	// Dump, load into a fresh DB, verify every UTXO is retrievable.
	params := new(ChainParams)
	*params = TestNetParams
	srcDB := newMemDB()
	bc, err := NewBlockchain(params, srcDB)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := BuildSnapshot(bc)
	if err != nil {
		t.Fatal(err)
	}
	// Should be non-empty because genesis creates a coinbase UTXO.
	if len(snap.UTXOs) == 0 {
		t.Fatal("genesis UTXO set is empty; snapshot would be trivial")
	}

	// Load into a new, empty UTXO set.
	dstDB := newMemDB()
	n, err := LoadSnapshot(dstDB, snap)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(snap.UTXOs) {
		t.Errorf("LoadSnapshot count: got %d, want %d", n, len(snap.UTXOs))
	}

	dstUTXO := NewUTXOSet(dstDB)
	for _, u := range snap.UTXOs {
		got, ok := dstUTXO.Get(primitives.OutPoint{TxID: u.TxID, Index: u.Index})
		if !ok {
			t.Errorf("UTXO %x:%d not found after load", u.TxID, u.Index)
			continue
		}
		if got.Value != u.Value || got.Height != u.Height {
			t.Errorf("UTXO %x:%d: loaded %+v, want %+v", u.TxID, u.Index, got, u)
		}
	}
}

func TestSnapshot_RejectsBadMagic(t *testing.T) {
	bad := make([]byte, 4+4+8+32+8)
	copy(bad[:4], []byte("XXXX"))
	if _, err := DeserializeSnapshot(bad); err == nil {
		t.Error("bad magic must be rejected")
	}
}

func TestSnapshot_RejectsBadVersion(t *testing.T) {
	snap := &Snapshot{Height: 1}
	raw := snap.Serialize()
	// Corrupt the version field.
	raw[4] = 0xff
	if _, err := DeserializeSnapshot(raw); err == nil {
		t.Error("unknown version must be rejected")
	}
}
