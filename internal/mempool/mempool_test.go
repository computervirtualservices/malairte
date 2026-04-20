package mempool

import (
	"testing"

	"github.com/computervirtualservices/malairte/internal/primitives"
)

// defaultFee is the fee used by tests that don't care about fee ordering.
const defaultFee int64 = 1_000

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
	if err := pool.Add(tx, defaultFee); err != nil {
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
	if err := pool.Add(nil, defaultFee); err == nil {
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
	if err := pool.Add(cb, defaultFee); err == nil {
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
	if err := pool.Add(tx, defaultFee); err == nil {
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
	if err := pool.Add(tx, defaultFee); err == nil {
		t.Error("expected error for tx with no outputs")
	}
}

func TestAdd_ZeroOutputValue(t *testing.T) {
	pool := NewTxPool()
	tx := makeTx(someID(1), 0, 0)
	if err := pool.Add(tx, defaultFee); err == nil {
		t.Error("expected error for zero output value")
	}
}

func TestAdd_NegativeOutputValue(t *testing.T) {
	pool := NewTxPool()
	tx := makeTx(someID(1), 0, -500)
	if err := pool.Add(tx, defaultFee); err == nil {
		t.Error("expected error for negative output value")
	}
}

func TestAdd_Duplicate(t *testing.T) {
	pool := NewTxPool()
	tx := makeTx(someID(1), 0, 1_000_000)
	if err := pool.Add(tx, defaultFee); err != nil {
		t.Fatalf("first Add: %v", err)
	}
	if err := pool.Add(tx, defaultFee); err == nil {
		t.Error("expected error adding duplicate tx")
	}
	if pool.Count() != 1 {
		t.Errorf("Count after duplicate: got %d, want 1", pool.Count())
	}
}

func TestAdd_NegativeFee(t *testing.T) {
	pool := NewTxPool()
	tx := makeTx(someID(1), 0, 1_000)
	if err := pool.Add(tx, -1); err == nil {
		t.Error("expected error for negative fee")
	}
}

// ── Remove / RemoveBlock ──────────────────────────────────────────────────────

func TestRemove_Present(t *testing.T) {
	pool := NewTxPool()
	tx := makeTx(someID(1), 0, 1_000_000)
	_ = pool.Add(tx, defaultFee)
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
	_ = pool.Add(tx1, defaultFee)
	_ = pool.Add(tx2, defaultFee)
	_ = pool.Add(tx3, defaultFee)

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
	_ = pool.Add(tx, defaultFee)
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

// ── GetSorted (now fee-rate ordered, not output-value) ────────────────────────

func TestGetSorted_DescendingOrder(t *testing.T) {
	pool := NewTxPool()
	// Three txs of comparable size; feerate is proportional to fee so the
	// sort order follows fee descending.
	low := makeTx(someID(1), 0, 1_000)
	mid := makeTx(someID(2), 0, 1_000)
	high := makeTx(someID(3), 0, 1_000)
	_ = pool.Add(low, 100)
	_ = pool.Add(mid, 500)
	_ = pool.Add(high, 2000)

	sorted := pool.GetSorted(10)
	if len(sorted) != 3 {
		t.Fatalf("GetSorted: got %d txs, want 3", len(sorted))
	}
	if sorted[0].TxID() != high.TxID() {
		t.Error("GetSorted: expected highest-feerate tx first")
	}
	if sorted[2].TxID() != low.TxID() {
		t.Error("GetSorted: expected lowest-feerate tx last")
	}
}

func TestGetSorted_MaxCount(t *testing.T) {
	pool := NewTxPool()
	for i := byte(1); i <= 5; i++ {
		_ = pool.Add(makeTx(someID(i), 0, int64(i)*1_000), int64(i)*100)
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
	_ = pool.Add(makeTx(someID(1), 0, 1_000), defaultFee)
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
	_ = pool.Add(makeTx(someID(1), 0, 1_000), defaultFee)
	_ = pool.Add(makeTx(someID(2), 0, 2_000), defaultFee)
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
	_ = pool.Add(tx, defaultFee)
	want := len(tx.Serialize())
	if pool.Size() != want {
		t.Errorf("Size: got %d, want %d", pool.Size(), want)
	}
}

func TestGetAll(t *testing.T) {
	pool := NewTxPool()
	tx1 := makeTx(someID(1), 0, 1_000_000)
	tx2 := makeTx(someID(2), 0, 2_000_000)
	_ = pool.Add(tx1, defaultFee)
	_ = pool.Add(tx2, defaultFee)
	all := pool.GetAll()
	if len(all) != 2 {
		t.Errorf("GetAll: got %d txs, want 2", len(all))
	}
}

// ── RBF (full replace-by-fee) ─────────────────────────────────────────────────

// makeConflicting builds two txs that spend the same outpoint but produce
// different txids (via different output values).
func makeConflicting(prevTxID [32]byte, index uint32, outValueA, outValueB int64) (*primitives.Transaction, *primitives.Transaction) {
	a := makeTx(prevTxID, index, outValueA)
	b := makeTx(prevTxID, index, outValueB)
	return a, b
}

func TestRBF_HigherFeerateEvictsConflict(t *testing.T) {
	pool := NewTxPool()
	orig, replacement := makeConflicting(someID(0xAA), 0, 1_000, 900)

	if err := pool.Add(orig, 100); err != nil {
		t.Fatalf("add original: %v", err)
	}
	// 2× fee on a same-size tx comfortably beats the 1.1× bump rule.
	if err := pool.Add(replacement, 500); err != nil {
		t.Fatalf("add replacement: %v", err)
	}
	if pool.Has(orig.TxID()) {
		t.Error("original must be evicted by higher-feerate replacement")
	}
	if !pool.Has(replacement.TxID()) {
		t.Error("replacement must be present after RBF")
	}
	if pool.Count() != 1 {
		t.Errorf("pool count after RBF: got %d, want 1", pool.Count())
	}
}

func TestRBF_LowerFeerateRejected(t *testing.T) {
	pool := NewTxPool()
	orig, replacement := makeConflicting(someID(0xBB), 0, 1_000, 900)
	if err := pool.Add(orig, 500); err != nil {
		t.Fatal(err)
	}
	// Same fee → fails the 1.1× bump rule.
	if err := pool.Add(replacement, 500); err == nil {
		t.Error("equal-fee replacement must be rejected")
	}
	if !pool.Has(orig.TxID()) {
		t.Error("original must remain after rejected RBF")
	}
}

func TestRBF_BumpRuleJustBarelyFails(t *testing.T) {
	pool := NewTxPool()
	orig, replacement := makeConflicting(someID(0xCC), 0, 1_000, 900)
	// orig fee 100; 1.1× → requires newFeerate > 110 atoms/vB per the
	// same-size comparison. A 105-fee replacement must be rejected.
	_ = pool.Add(orig, 100)
	if err := pool.Add(replacement, 105); err == nil {
		t.Error("1.05× replacement must be rejected by 1.1× bump rule")
	}
}

func TestRBF_MultipleConflictsAllEvicted(t *testing.T) {
	// Replacement that spends two outpoints currently claimed by separate
	// mempool txs must evict both when it wins.
	pool := NewTxPool()
	a := makeTx(someID(0xD1), 0, 1_000)
	b := makeTx(someID(0xD2), 0, 1_000)
	_ = pool.Add(a, 200)
	_ = pool.Add(b, 300)

	// Replacement spends both a's and b's outpoints.
	replacement := &primitives.Transaction{
		Version: 1,
		Inputs: []primitives.TxInput{
			{PreviousOutput: primitives.OutPoint{TxID: someID(0xD1), Index: 0}, Sequence: 0xFFFFFFFF},
			{PreviousOutput: primitives.OutPoint{TxID: someID(0xD2), Index: 0}, Sequence: 0xFFFFFFFF},
		},
		Outputs: []primitives.TxOutput{{Value: 1_500, ScriptPubKey: []byte{0x51}}},
	}
	// combined old fee = 500; need > 500 × 1.1 in feerate and ≥ 500 + vsize
	// absolute. 2000 is plenty at this tx size.
	if err := pool.Add(replacement, 2_000); err != nil {
		t.Fatalf("multi-conflict RBF: %v", err)
	}
	if pool.Has(a.TxID()) || pool.Has(b.TxID()) {
		t.Error("both original txs must be evicted")
	}
	if !pool.Has(replacement.TxID()) {
		t.Error("replacement must be present")
	}
	if pool.Count() != 1 {
		t.Errorf("pool count: got %d, want 1", pool.Count())
	}
}

// ── Package relay / CPFP ──────────────────────────────────────────────────────

func TestGetOutput_MempoolParentLookup(t *testing.T) {
	pool := NewTxPool()
	parent := makeTx(someID(0xF1), 0, 800)
	_ = pool.Add(parent, 100)

	got, ok := pool.GetOutput(primitives.OutPoint{TxID: parent.TxID(), Index: 0})
	if !ok {
		t.Fatal("GetOutput: expected mempool lookup to succeed")
	}
	if got.Value != 800 {
		t.Errorf("GetOutput value: got %d, want 800", got.Value)
	}

	// Out-of-range index → not found.
	if _, ok := pool.GetOutput(primitives.OutPoint{TxID: parent.TxID(), Index: 5}); ok {
		t.Error("GetOutput with out-of-range index must return false")
	}
	// Unknown txid → not found.
	if _, ok := pool.GetOutput(primitives.OutPoint{TxID: someID(0xDE), Index: 0}); ok {
		t.Error("GetOutput with unknown txid must return false")
	}
}

// buildChild constructs a tx whose single input spends parent's output 0
// with the given output value.
func buildChild(parent *primitives.Transaction, outValue int64) *primitives.Transaction {
	return &primitives.Transaction{
		Version: 1,
		Inputs: []primitives.TxInput{{
			PreviousOutput: primitives.OutPoint{TxID: parent.TxID(), Index: 0},
			Sequence:       0xFFFFFFFF,
		}},
		Outputs: []primitives.TxOutput{{Value: outValue, ScriptPubKey: []byte{0x51}}},
	}
}

func TestCPFP_ChildAcceptedAfterParent(t *testing.T) {
	// The pool itself doesn't check UTXO availability — that's the caller's
	// job. What this test proves is that GetOutput returns the right parent
	// output, so a caller computing fee = sumIn − sumOut on the child will
	// resolve the parent's output through the mempool and produce a valid
	// fee. We simulate the caller inline.
	pool := NewTxPool()
	parent := makeTx(someID(0xA1), 0, 1_000)
	_ = pool.Add(parent, 50)

	child := buildChild(parent, 900) // 100 atoms fee available via CPFP lookup

	// Caller-side fee computation: UTXO set miss → pool.GetOutput.
	out, ok := pool.GetOutput(child.Inputs[0].PreviousOutput)
	if !ok {
		t.Fatal("parent output must be resolvable via GetOutput")
	}
	fee := out.Value - child.Outputs[0].Value
	if fee != 100 {
		t.Errorf("fee: got %d, want 100", fee)
	}

	if err := pool.Add(child, fee); err != nil {
		t.Fatalf("child Add: %v", err)
	}
	if !pool.Has(child.TxID()) {
		t.Error("child must be present in mempool")
	}
	if pool.Count() != 2 {
		t.Errorf("Count: got %d, want 2", pool.Count())
	}
}

func TestCascadeEviction_RemoveParentRemovesChild(t *testing.T) {
	pool := NewTxPool()
	parent := makeTx(someID(0xB1), 0, 1_000)
	_ = pool.Add(parent, 50)
	child := buildChild(parent, 900)
	_ = pool.Add(child, 100)
	if pool.Count() != 2 {
		t.Fatalf("setup: Count=%d, want 2", pool.Count())
	}

	pool.Remove(parent.TxID())

	if pool.Has(parent.TxID()) {
		t.Error("parent must be removed")
	}
	if pool.Has(child.TxID()) {
		t.Error("child must be cascade-removed when parent is removed")
	}
	if pool.Count() != 0 {
		t.Errorf("Count after cascade: got %d, want 0", pool.Count())
	}
}

func TestRemoveBlock_PreservesUnconfirmedChildren(t *testing.T) {
	// When a parent is confirmed in a block but its child is NOT in that
	// block, the child must stay in the mempool. Its inputs now reference
	// live UTXOs (the block.Apply caller promotes the parent's outputs to
	// the UTXO set), so the child is still valid and will be mined next.
	// This is the CPFP payoff: a low-fee parent rides into a block on its
	// high-fee child, then the child mines next.
	pool := NewTxPool()
	parent := makeTx(someID(0xC1), 0, 1_000)
	child := buildChild(parent, 900)
	_ = pool.Add(parent, 50)
	_ = pool.Add(child, 100)

	block := &primitives.Block{Txs: []*primitives.Transaction{parent}}
	pool.RemoveBlock(block)

	if pool.Has(parent.TxID()) {
		t.Error("parent must be removed by RemoveBlock")
	}
	if !pool.Has(child.TxID()) {
		t.Error("child of a confirmed parent must remain in mempool (CPFP)")
	}
	if pool.Count() != 1 {
		t.Errorf("Count after RemoveBlock: got %d, want 1", pool.Count())
	}
}

func TestRemoveBlock_RemovesBothWhenBothConfirmed(t *testing.T) {
	// If the block includes BOTH parent and child, both leave the mempool.
	pool := NewTxPool()
	parent := makeTx(someID(0xC2), 0, 1_000)
	child := buildChild(parent, 900)
	_ = pool.Add(parent, 50)
	_ = pool.Add(child, 100)

	block := &primitives.Block{Txs: []*primitives.Transaction{parent, child}}
	pool.RemoveBlock(block)

	if pool.Count() != 0 {
		t.Errorf("Count after both-confirmed RemoveBlock: got %d, want 0", pool.Count())
	}
}

func TestCascadeEviction_RBFEvictsParentRemovesChild(t *testing.T) {
	pool := NewTxPool()
	parent := makeTx(someID(0xD3), 0, 1_000)
	_ = pool.Add(parent, 50)
	child := buildChild(parent, 900)
	_ = pool.Add(child, 100)

	// Build a replacement that conflicts with parent (same input outpoint,
	// different output amount → different txid).
	replacement := makeTx(someID(0xD3), 0, 800)
	// Feerate vastly higher so RBF bump + bandwidth rules pass.
	if err := pool.Add(replacement, 1_000); err != nil {
		t.Fatalf("RBF replacement: %v", err)
	}

	if pool.Has(parent.TxID()) {
		t.Error("original parent must be evicted by RBF")
	}
	if pool.Has(child.TxID()) {
		t.Error("child must be cascade-removed when parent is RBF-evicted")
	}
	if !pool.Has(replacement.TxID()) {
		t.Error("replacement must be present")
	}
}

func TestCascadeEviction_DeepChain(t *testing.T) {
	// grandparent → parent → child: removing grandparent must cascade all.
	pool := NewTxPool()
	gp := makeTx(someID(0xE1), 0, 1_000)
	_ = pool.Add(gp, 50)
	parent := buildChild(gp, 900)
	_ = pool.Add(parent, 50)
	grandchild := buildChild(parent, 800)
	_ = pool.Add(grandchild, 50)
	if pool.Count() != 3 {
		t.Fatalf("setup Count=%d, want 3", pool.Count())
	}

	pool.Remove(gp.TxID())
	if pool.Count() != 0 {
		t.Errorf("deep cascade Count=%d, want 0", pool.Count())
	}
}

func TestFeeOf_ReturnsStoredFee(t *testing.T) {
	pool := NewTxPool()
	tx := makeTx(someID(0xEE), 0, 1_000)
	_ = pool.Add(tx, 777)
	fee, feerate, ok := pool.FeeOf(tx.TxID())
	if !ok {
		t.Fatal("FeeOf: not found")
	}
	if fee != 777 {
		t.Errorf("fee: got %d, want 777", fee)
	}
	if feerate <= 0 {
		t.Errorf("feerate: got %d, want > 0", feerate)
	}
}
