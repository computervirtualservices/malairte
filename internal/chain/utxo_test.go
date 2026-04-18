package chain

import (
	"sync"
	"testing"

	"github.com/computervirtualservices/malairte/internal/primitives"
	"github.com/computervirtualservices/malairte/internal/storage"
)

// ── in-memory DB for tests ────────────────────────────────────────────────────

type memDB struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func newMemDB() *memDB { return &memDB{data: make(map[string][]byte)} }

func (m *memDB) Put(key, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(value))
	copy(cp, value)
	m.data[string(key)] = cp
	return nil
}

func (m *memDB) Get(key []byte) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.data[string(key)]
	if !ok {
		return nil, storage.ErrNotFound
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	return cp, nil
}

func (m *memDB) Delete(key []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, string(key))
	return nil
}

func (m *memDB) Has(key []byte) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.data[string(key)]
	return ok, nil
}

func (m *memDB) Close() error { return nil }

func (m *memDB) ForEachWithPrefix(prefix []byte, fn func(key, value []byte) error) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p := string(prefix)
	for k, v := range m.data {
		if len(k) >= len(p) && k[:len(p)] == p {
			if err := fn([]byte(k), v); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *memDB) NewBatch() storage.Batch { return &memBatch{db: m} }

type memBatch struct {
	db  *memDB
	ops []batchOp
}

type batchOp struct {
	key    []byte
	value  []byte
	delete bool
}

func (b *memBatch) Put(key, value []byte) {
	cp := make([]byte, len(value))
	copy(cp, value)
	b.ops = append(b.ops, batchOp{key: append([]byte{}, key...), value: cp})
}

func (b *memBatch) Delete(key []byte) {
	b.ops = append(b.ops, batchOp{key: append([]byte{}, key...), delete: true})
}

func (b *memBatch) Write() error {
	b.db.mu.Lock()
	defer b.db.mu.Unlock()
	for _, op := range b.ops {
		if op.delete {
			delete(b.db.data, string(op.key))
		} else {
			b.db.data[string(op.key)] = op.value
		}
	}
	return nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

// makeBlock builds a simple block with one coinbase and one optional spend tx.
// The coinbase creates one output of value `rewardAtoms`.
// If spendOut is non-zero, a spend tx consuming the genesis coinbase is also added.
func makeTestBlock(height uint64, prevHash [32]byte, coinbaseValue int64) *primitives.Block {
	coinbaseTx := &primitives.Transaction{
		Version: 1,
		Inputs: []primitives.TxInput{{
			PreviousOutput: primitives.OutPoint{TxID: [32]byte{}, Index: 0xFFFFFFFF},
			Sequence:       0xFFFFFFFF,
		}},
		Outputs: []primitives.TxOutput{{
			Value:        coinbaseValue,
			ScriptPubKey: []byte{0x51}, // OP_1 (burn-style, not P2PKH)
		}},
	}
	txs := []*primitives.Transaction{coinbaseTx}
	merkleRoot := primitives.CalcMerkleRoot(txs)
	return &primitives.Block{
		Header: primitives.BlockHeader{
			Version:      1,
			PreviousHash: prevHash,
			MerkleRoot:   merkleRoot,
			Height:       height,
			Bits:         0x207fffff,
		},
		Txs: txs,
	}
}

// ── UTXOSet.Apply tests ───────────────────────────────────────────────────────

func TestUTXOSet_Apply_AddsNewUTXOs(t *testing.T) {
	db := newMemDB()
	us := NewUTXOSet(db)

	block := makeTestBlock(1, [32]byte{}, 5_000_000_000)
	if err := us.Apply(block); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// Coinbase output should now exist in UTXO set
	txID := block.Txs[0].TxID()
	op := primitives.OutPoint{TxID: txID, Index: 0}
	utxo, found := us.Get(op)
	if !found {
		t.Fatal("coinbase UTXO not found after Apply")
	}
	if utxo.Value != 5_000_000_000 {
		t.Errorf("value: got %d, want %d", utxo.Value, 5_000_000_000)
	}
	if !utxo.IsCoinbase {
		t.Error("coinbase UTXO should have IsCoinbase=true")
	}
}

func TestUTXOSet_Apply_StoresUndoData(t *testing.T) {
	db := newMemDB()
	us := NewUTXOSet(db)

	// Apply a block with a coinbase
	block0 := makeTestBlock(0, [32]byte{}, 5_000_000_000)
	if err := us.Apply(block0); err != nil {
		t.Fatalf("Apply block0: %v", err)
	}

	// Create a block that spends the coinbase output.
	// Use NewCoinbaseTx with height=1 so its TxID differs from block0's coinbase.
	cbTxID := block0.Txs[0].TxID()
	spendTx := &primitives.Transaction{
		Version: 1,
		Inputs: []primitives.TxInput{{
			PreviousOutput: primitives.OutPoint{TxID: cbTxID, Index: 0},
			Sequence:       0xFFFFFFFF,
		}},
		Outputs: []primitives.TxOutput{{
			Value:        4_999_000_000,
			ScriptPubKey: []byte{0x51},
		}},
	}
	coinbaseTx := primitives.NewCoinbaseTx(1, 5_000_000_000, []byte{0x51}, 0)
	txs := []*primitives.Transaction{coinbaseTx, spendTx}
	block1 := &primitives.Block{
		Header: primitives.BlockHeader{
			Version:      1,
			PreviousHash: block0.Header.Hash(),
			MerkleRoot:   primitives.CalcMerkleRoot(txs),
			Height:       1,
			Bits:         0x207fffff,
		},
		Txs: txs,
	}

	if err := us.Apply(block1); err != nil {
		t.Fatalf("Apply block1: %v", err)
	}

	// The spent coinbase UTXO should no longer exist
	op := primitives.OutPoint{TxID: cbTxID, Index: 0}
	if _, found := us.Get(op); found {
		t.Error("spent UTXO should not be present after Apply")
	}

	// Undo data should have been stored
	undoBytes, err := db.Get(undoKey(block1.Header.Hash()))
	if err != nil {
		t.Fatalf("undo data not found: %v", err)
	}
	if len(undoBytes) == 0 {
		t.Error("undo data is empty")
	}

	// Decode and verify it references the spent UTXO
	spent, err := deserializeUndoData(undoBytes)
	if err != nil {
		t.Fatalf("deserialize undo data: %v", err)
	}
	if len(spent) != 1 {
		t.Fatalf("expected 1 spent UTXO, got %d", len(spent))
	}
	if spent[0].outPoint != op {
		t.Errorf("undo outpoint mismatch: got %x:%d, want %x:%d",
			spent[0].outPoint.TxID, spent[0].outPoint.Index,
			op.TxID, op.Index)
	}
	if spent[0].utxo.Value != 5_000_000_000 {
		t.Errorf("undo value: got %d, want 5000000000", spent[0].utxo.Value)
	}
}

// ── UTXOSet.Revert tests ──────────────────────────────────────────────────────

func TestUTXOSet_Revert_RestoresSpentUTXOs(t *testing.T) {
	db := newMemDB()
	us := NewUTXOSet(db)

	// Apply a coinbase block at height 0
	block0 := makeTestBlock(0, [32]byte{}, 5_000_000_000)
	if err := us.Apply(block0); err != nil {
		t.Fatalf("Apply block0: %v", err)
	}
	cbTxID := block0.Txs[0].TxID()
	cbOP := primitives.OutPoint{TxID: cbTxID, Index: 0}

	// Build block1 with a distinct coinbase (height=1 changes the scriptSig via NewCoinbaseTx)
	// and a spend transaction consuming block0's coinbase output.
	spendTx := &primitives.Transaction{
		Version: 1,
		Inputs: []primitives.TxInput{{
			PreviousOutput: cbOP,
			Sequence:       0xFFFFFFFF,
		}},
		Outputs: []primitives.TxOutput{{
			Value:        4_999_000_000,
			ScriptPubKey: []byte{0x51},
		}},
	}
	// Use height=1 in the coinbase so its serialization (and TxID) differs from block0's coinbase
	block1CoinbaseTx := primitives.NewCoinbaseTx(1, 5_000_000_000, []byte{0x51}, 0)
	txs := []*primitives.Transaction{block1CoinbaseTx, spendTx}
	block1 := &primitives.Block{
		Header: primitives.BlockHeader{
			Version:      1,
			PreviousHash: block0.Header.Hash(),
			MerkleRoot:   primitives.CalcMerkleRoot(txs),
			Height:       1,
			Bits:         0x207fffff,
		},
		Txs: txs,
	}
	if err := us.Apply(block1); err != nil {
		t.Fatalf("Apply block1: %v", err)
	}

	// Confirm block0's coinbase UTXO is gone (spent by block1)
	if _, found := us.Get(cbOP); found {
		t.Error("block0 coinbase UTXO should be consumed after Apply(block1)")
	}

	// Revert block1 — the coinbase UTXO from block0 should come back
	if err := us.Revert(block1); err != nil {
		t.Fatalf("Revert: %v", err)
	}

	// block0's coinbase UTXO should be restored
	utxo, found := us.Get(cbOP)
	if !found {
		t.Fatal("UTXO not restored after Revert")
	}
	if utxo.Value != 5_000_000_000 {
		t.Errorf("restored value: got %d, want 5000000000", utxo.Value)
	}

	// block1's outputs should be gone
	block1CbTxID := block1CoinbaseTx.TxID()
	if _, found := us.Get(primitives.OutPoint{TxID: block1CbTxID, Index: 0}); found {
		t.Error("block1 coinbase UTXO should not exist after Revert")
	}
	spendTxID := spendTx.TxID()
	if _, found := us.Get(primitives.OutPoint{TxID: spendTxID, Index: 0}); found {
		t.Error("block1 spend UTXO should not exist after Revert")
	}

	// Undo data for block1 should have been cleaned up
	if _, err := db.Get(undoKey(block1.Header.Hash())); err == nil {
		t.Error("undo data should be deleted after successful Revert")
	}
}

func TestUTXOSet_Revert_ErrorsWithoutUndoData(t *testing.T) {
	db := newMemDB()
	us := NewUTXOSet(db)

	// Try to revert a block that was never applied (no undo data)
	phantom := makeTestBlock(99, [32]byte{0xDE, 0xAD}, 1_000)
	if err := us.Revert(phantom); err == nil {
		t.Error("expected error reverting block with no undo data, got nil")
	}
}

// ── serializeUndoData round-trip ──────────────────────────────────────────────

func TestUndoDataRoundTrip(t *testing.T) {
	spent := []spentUTXO{
		{
			outPoint: primitives.OutPoint{TxID: [32]byte{0xAA}, Index: 1},
			utxo:     UTXO{Value: 1_000_000, Height: 5, IsCoinbase: true, Script: []byte{0x51}},
		},
		{
			outPoint: primitives.OutPoint{TxID: [32]byte{0xBB}, Index: 2},
			utxo:     UTXO{Value: 2_000_000, Height: 10, IsCoinbase: false, Script: []byte{0x76, 0xa9}},
		},
	}

	encoded := serializeUndoData(spent)
	decoded, err := deserializeUndoData(encoded)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if len(decoded) != len(spent) {
		t.Fatalf("count: got %d, want %d", len(decoded), len(spent))
	}
	for i, s := range spent {
		if decoded[i].outPoint != s.outPoint {
			t.Errorf("[%d] outpoint mismatch", i)
		}
		if decoded[i].utxo.Value != s.utxo.Value {
			t.Errorf("[%d] value: got %d, want %d", i, decoded[i].utxo.Value, s.utxo.Value)
		}
		if decoded[i].utxo.Height != s.utxo.Height {
			t.Errorf("[%d] height: got %d, want %d", i, decoded[i].utxo.Height, s.utxo.Height)
		}
		if decoded[i].utxo.IsCoinbase != s.utxo.IsCoinbase {
			t.Errorf("[%d] IsCoinbase: got %v, want %v", i, decoded[i].utxo.IsCoinbase, s.utxo.IsCoinbase)
		}
	}
}

func TestUndoDataEmptyBlock(t *testing.T) {
	// A coinbase-only block has no spent UTXOs
	var spent []spentUTXO
	encoded := serializeUndoData(spent)
	decoded, err := deserializeUndoData(encoded)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if len(decoded) != 0 {
		t.Errorf("expected 0 spent UTXOs, got %d", len(decoded))
	}
}
