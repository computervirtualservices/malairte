package mempool

import (
	"testing"

	"github.com/computervirtualservices/malairte/internal/primitives"
)

func TestOrphanPool_AddHasRemove(t *testing.T) {
	p := NewOrphanPool(10)
	tx := makeTx(someID(0x01), 0, 1_000)
	p.Add(tx)
	if !p.Has(tx.TxID()) {
		t.Error("orphan must be present after Add")
	}
	if p.Count() != 1 {
		t.Errorf("Count: got %d, want 1", p.Count())
	}
	// Adding again is a no-op.
	p.Add(tx)
	if p.Count() != 1 {
		t.Errorf("duplicate Add must not grow pool")
	}
}

func TestOrphanPool_ReleaseByParent(t *testing.T) {
	// Two orphans share the same parent-txid as their input's prevout.
	// When that parent is finally admitted, Release should return both.
	p := NewOrphanPool(10)
	parentTxID := someID(0x77)
	childA := makeTx(parentTxID, 0, 500)
	childB := makeTx(parentTxID, 1, 300) // different index → distinct txid
	p.Add(childA)
	p.Add(childB)
	if p.Count() != 2 {
		t.Fatalf("setup Count=%d, want 2", p.Count())
	}

	released := p.Release(parentTxID)
	if len(released) != 2 {
		t.Errorf("Release: got %d orphans, want 2", len(released))
	}
	// Both must be removed from the pool.
	if p.Has(childA.TxID()) || p.Has(childB.TxID()) {
		t.Error("released orphans must leave the pool")
	}
	if p.Count() != 0 {
		t.Errorf("Count after release: got %d, want 0", p.Count())
	}
}

func TestOrphanPool_ReleaseUnrelatedParent(t *testing.T) {
	p := NewOrphanPool(10)
	child := makeTx(someID(0x01), 0, 500)
	p.Add(child)
	released := p.Release(someID(0xFF)) // different parent
	if len(released) != 0 {
		t.Error("Release with unrelated parent must return nothing")
	}
	if !p.Has(child.TxID()) {
		t.Error("unrelated orphan must stay in the pool")
	}
}

func TestOrphanPool_CapacityEviction(t *testing.T) {
	// Fill to capacity, then add one more: Count must still equal cap.
	const cap = 5
	p := NewOrphanPool(cap)
	for i := byte(1); i <= cap; i++ {
		p.Add(makeTx(someID(i), 0, int64(i)*100))
	}
	if p.Count() != cap {
		t.Fatalf("setup Count=%d, want %d", p.Count(), cap)
	}
	overflow := makeTx(someID(0xEE), 0, 9_999)
	p.Add(overflow)
	if p.Count() != cap {
		t.Errorf("after overflow Count=%d, want %d (eviction should keep cap)", p.Count(), cap)
	}
	// The new orphan must have been added.
	if !p.Has(overflow.TxID()) {
		t.Error("overflow orphan must be present after eviction")
	}
}

func TestOrphanPool_MultipleParentsIndexedSeparately(t *testing.T) {
	// A single orphan with multiple inputs is indexed under every parent —
	// any one of them arriving triggers the orphan's release.
	p := NewOrphanPool(10)
	parent1 := someID(0xA1)
	parent2 := someID(0xB2)
	tx := &primitives.Transaction{
		Version: 1,
		Inputs: []primitives.TxInput{
			{PreviousOutput: primitives.OutPoint{TxID: parent1, Index: 0}, Sequence: 0xFFFFFFFF},
			{PreviousOutput: primitives.OutPoint{TxID: parent2, Index: 0}, Sequence: 0xFFFFFFFF},
		},
		Outputs: []primitives.TxOutput{{Value: 1_000, ScriptPubKey: []byte{0x51}}},
	}
	p.Add(tx)

	// Releasing under parent1 gets us the orphan.
	released := p.Release(parent1)
	if len(released) != 1 {
		t.Errorf("release by parent1: got %d, want 1", len(released))
	}
	// Now parent2's index should also have been cleared.
	if got := p.Release(parent2); len(got) != 0 {
		t.Error("orphan released by parent1 must not appear under parent2 again")
	}
}
