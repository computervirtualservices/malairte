package mempool

import (
	"testing"

	"github.com/malairt/malairt/internal/primitives"
)

// makeTx builds a minimal valid non-coinbase transaction for testing.
// prevTxID must not be all-zeros (which would make index 0xFFFFFFFF a coinbase).
func makeTx(prevTxID [32]byte, index uint32, value int64) *primitives.Transaction {
	return &primitives.Transaction{
		Version: 1,
		Inputs: []primitives.TxInput{{
			PreviousOutput: primitives.OutPoint{TxID: prevTxID, Index: index},
			Sequence:       0xFFFFFFFF,
		}},
		Outputs: []primitives.TxOutput{{
			Value:        value,
			ScriptPubKey: []byte{0x51},
		}},
	}
}

// someID returns a [32]byte with the given byte in position 0.
func someID(b byte) [32]byte {
	var id [32]byte
	id[0] = b
	return id
}

// ── Add ───────────────────────────────────────────────────────────────────────

func TestAdd_Valid(t *testing.T) {
	pool := NewTxPool()
	tx := makeTx(someID(1), 0, 1_000_000)
	if err := pool.Add(tx); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if pool.Count() != 1 {
		t.Errorf("Count: got %d, want 1", pool.Count())
	}
	if !pool.Has(tx.TxID()) {
		t.Error("Has: expected true after Add")
	}
}

func TestAdd_Nil(t *testing.T) {
	pool := NewTxPool()
	if err := pool.Add(nil); err == nil {
		t.Error("expected error adding nil tx")
	}
}

func TestAdd_Coinbase(t *testing.T) {
	pool := NewTxPool()
	cb := &primitives.Transaction{
		Version: 1,
		Inputs: []primitives.TxInput{{
			PreviousOutput: primitives.OutPoint{TxID: [32]byte{}, Index: 0xFFFFFFFF},
			Sequence:       0xFFFFFFFF,
		}},
		Outputs: []primitives.TxOutput{{Value: 5_000_000_000, ScriptPubKey: []byte{0x51}}},
	}
	if err := pool.Add(cb); err == nil {
		t.Error("expected error adding coinbase tx")
	}
}

func TestAdd_NoInputs(t *testing.T) {
	pool := NewTxPool()
	tx := &primitives.Transaction{
		Version: 1,
		Inputs:  []primitives.TxInput{},
		Outputs: []primitives.TxOutput{{Value: 1_000, ScriptPubKey: []byte{0x51}}},
	}
	if err := pool.Add(tx); err == nil {
		t.Error("expected error for tx with no inputs")
	}
}

func TestAdd_NoOutputs(t *testing.T) {
	pool := NewTxPool()
	tx := &primitives.Transaction{
		Version: 1,
		Inputs: []primitives.TxInput{{
			PreviousOutput: primitives.OutPoint{TxID: someID(1), Index: 0},
			Sequence:       0xFFFFFFFF,
		}},
		Outputs: []primitives.TxOutput{},
	}
	if err := pool.Add(tx); err == nil {
		t.Error("expected error for tx with no outputs")
	}
}

func TestAdd_ZeroOutputValue(t *testing.T) {
	pool := NewTxPool()
	tx := makeTx(someID(1), 0, 0)
	if err := pool.Add(tx); err == nil {
		t.Error("expected error for zero output value")
	}
}

func TestAdd_NegativeOutputValue(t *testing.T) {
	pool := NewTxPool()
	tx := makeTx(someID(1), 0, -500)
	if err := pool.Add(tx); err == nil {
		t.Error("expected error for negative output value")
	}
}

func TestAdd_Duplicate(t *testing.T) {
	pool := NewTxPool()
	tx := makeTx(someID(1), 0, 1_000_000)
	if err := pool.Add(tx); err != nil {
		t.Fatalf("first Add: %v", err)
	}
	if err := pool.Add(tx); err == nil {
		t.Error("expected error adding duplicate tx")
	}
	if pool.Count() != 1 {
		t.Errorf("Count after duplicate: got %d, want 1", pool.Count())
	}
}

// ── Remove / RemoveBlock ──────────────────────────────────────────────────────

func TestRemove_Present(t *testing.T) {
	pool := NewTxPool()
	tx := makeTx(someID(1), 0, 1_000_000)
	_ = pool.Add(tx)
	txid := tx.TxID()
	pool.Remove(txid)
	if pool.Has(txid) {
		t.Error("Has: expected false after Remove")
	}
	if pool.Count() != 0 {
		t.Errorf("Count after Remove: got %d, want 0", pool.Count())
	}
}

func TestRemove_NotPresent(t *testing.T) {
	pool := NewTxPool()
	// Remove of a non-existent txid must be a no-op.
	pool.Remove(someID(0xAB))
	if pool.Count() != 0 {
		t.Errorf("Count: got %d, want 0", pool.Count())
	}
}

func TestRemoveBlock(t *testing.T) {
	pool := NewTxPool()
	tx1 := makeTx(someID(1), 0, 1_000_000)
	tx2 := makeTx(someID(2), 0, 2_000_000)
	tx3 := makeTx(someID(3), 0, 3_000_000)
	_ = pool.Add(tx1)
	_ = pool.Add(tx2)
	_ = pool.Add(tx3)

	block := &primitives.Block{Txs: []*primitives.Transaction{tx1, tx2}}
	pool.RemoveBlock(block)

	if pool.Has(tx1.TxID()) {
		t.Error("tx1 should be removed after RemoveBlock")
	}
	if pool.Has(tx2.TxID()) {
		t.Error("tx2 should be removed after RemoveBlock")
	}
	if !pool.Has(tx3.TxID()) {
		t.Error("tx3 should remain after RemoveBlock")
	}
	if pool.Count() != 1 {
		t.Errorf("Count: got %d, want 1", pool.Count())
	}
}

// ── Get / Has ─────────────────────────────────────────────────────────────────

func TestGet_Found(t *testing.T) {
	pool := NewTxPool()
	tx := makeTx(someID(1), 0, 1_000_000)
	_ = pool.Add(tx)
	got, found := pool.Get(tx.TxID())
	if !found {
		t.Fatal("Get: not found")
	}
	if got.TxID() != tx.TxID() {
		t.Error("Get: returned wrong transaction")
	}
}

func TestGet_NotFound(t *testing.T) {
	pool := NewTxPool()
	got, found := pool.Get(someID(0xFF))
	if found {
		t.Error("Get: expected not found")
	}
	if got != nil {
		t.Error("Get: expected nil for missing tx")
	}
}

// ── GetSorted ─────────────────────────────────────────────────────────────────

func TestGetSorted_DescendingOrder(t *testing.T) {
	pool := NewTxPool()
	low := makeTx(someID(1), 0, 1_000)
	mid := makeTx(someID(2), 0, 5_000)
	high := makeTx(someID(3), 0, 9_000)
	_ = pool.Add(low)
	_ = pool.Add(mid)
	_ = pool.Add(high)

	sorted := pool.GetSorted(10)
	if len(sorted) != 3 {
		t.Fatalf("GetSorted: got %d txs, want 3", len(sorted))
	}
	if sorted[0].TxID() != high.TxID() {
		t.Error("GetSorted: expected high-value tx first")
	}
	if sorted[2].TxID() != low.TxID() {
		t.Error("GetSorted: expected low-value tx last")
	}
}

func TestGetSorted_MaxCount(t *testing.T) {
	pool := NewTxPool()
	for i := byte(1); i <= 5; i++ {
		_ = pool.Add(makeTx(someID(i), 0, int64(i)*1_000))
	}
	sorted := pool.GetSorted(3)
	if len(sorted) != 3 {
		t.Errorf("GetSorted(3): got %d txs, want 3", len(sorted))
	}
}

func TestGetSorted_Empty(t *testing.T) {
	pool := NewTxPool()
	sorted := pool.GetSorted(10)
	if len(sorted) != 0 {
		t.Errorf("GetSorted on empty pool: got %d txs, want 0", len(sorted))
	}
}

func TestGetSorted_MaxCountExceedsPoolSize(t *testing.T) {
	pool := NewTxPool()
	_ = pool.Add(makeTx(someID(1), 0, 1_000))
	sorted := pool.GetSorted(100)
	if len(sorted) != 1 {
		t.Errorf("GetSorted(100) on 1-tx pool: got %d, want 1", len(sorted))
	}
}

// ── Count / Size / GetAll ─────────────────────────────────────────────────────

func TestCount(t *testing.T) {
	pool := NewTxPool()
	if pool.Count() != 0 {
		t.Errorf("Count on empty pool: got %d, want 0", pool.Count())
	}
	_ = pool.Add(makeTx(someID(1), 0, 1_000))
	_ = pool.Add(makeTx(someID(2), 0, 2_000))
	if pool.Count() != 2 {
		t.Errorf("Count: got %d, want 2", pool.Count())
	}
}

func TestSize(t *testing.T) {
	pool := NewTxPool()
	if pool.Size() != 0 {
		t.Errorf("Size on empty pool: got %d, want 0", pool.Size())
	}
	tx := makeTx(someID(1), 0, 1_000_000)
	_ = pool.Add(tx)
	want := len(tx.Serialize())
	if pool.Size() != want {
		t.Errorf("Size: got %d, want %d", pool.Size(), want)
	}
}

func TestGetAll(t *testing.T) {
	pool := NewTxPool()
	tx1 := makeTx(someID(1), 0, 1_000_000)
	tx2 := makeTx(someID(2), 0, 2_000_000)
	_ = pool.Add(tx1)
	_ = pool.Add(tx2)
	all := pool.GetAll()
	if len(all) != 2 {
		t.Errorf("GetAll: got %d txs, want 2", len(all))
	}
}
