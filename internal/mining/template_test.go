package mining

import (
	"sync"
	"testing"

	"github.com/malairt/malairt/internal/chain"
	"github.com/malairt/malairt/internal/mempool"
	"github.com/malairt/malairt/internal/primitives"
	"github.com/malairt/malairt/internal/storage"
)

// ── in-memory DB for tests ────────────────────────────────────────────────────

type testDB struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func newTestDB() *testDB { return &testDB{data: make(map[string][]byte)} }

func (m *testDB) Put(key, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(value))
	copy(cp, value)
	m.data[string(key)] = cp
	return nil
}

func (m *testDB) Get(key []byte) ([]byte, error) {
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

func (m *testDB) Delete(key []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, string(key))
	return nil
}

func (m *testDB) Has(key []byte) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.data[string(key)]
	return ok, nil
}

func (m *testDB) Close() error { return nil }

func (m *testDB) ForEachWithPrefix(prefix []byte, fn func(key, value []byte) error) error {
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

func (m *testDB) NewBatch() storage.Batch { return &testBatch{db: m} }

type testBatch struct {
	db  *testDB
	ops []testBatchOp
}

type testBatchOp struct {
	key    []byte
	value  []byte
	delete bool
}

func (b *testBatch) Put(key, value []byte) {
	cp := make([]byte, len(value))
	copy(cp, value)
	b.ops = append(b.ops, testBatchOp{key: append([]byte{}, key...), value: cp})
}

func (b *testBatch) Delete(key []byte) {
	b.ops = append(b.ops, testBatchOp{key: append([]byte{}, key...), delete: true})
}

func (b *testBatch) Write() error {
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

// newTestBlockchain returns a Blockchain backed by an in-memory DB.
// The genesis block is written automatically by NewBlockchain.
func newTestBlockchain(t *testing.T) *chain.Blockchain {
	t.Helper()
	// Use a heap-allocated copy so NewBlockchain's GenesisHash write
	// does not mutate the package-level TestNetParams variable.
	params := new(chain.ChainParams)
	*params = chain.TestNetParams
	bc, err := chain.NewBlockchain(params, newTestDB())
	if err != nil {
		t.Fatalf("NewBlockchain: %v", err)
	}
	return bc
}

// populateUTXOs applies a block containing the given coinbase-style transactions
// to a fresh UTXOSet and returns the set.  Useful for setting up calcTxFee inputs.
func populateUTXOs(t *testing.T, txs ...*primitives.Transaction) *chain.UTXOSet {
	t.Helper()
	db := newTestDB()
	us := chain.NewUTXOSet(db)
	block := &primitives.Block{
		Header: primitives.BlockHeader{Height: 1, Bits: 0x207fffff},
		Txs:    txs,
	}
	if err := us.Apply(block); err != nil {
		t.Fatalf("UTXOSet.Apply: %v", err)
	}
	return us
}

// ── calcTxFee ─────────────────────────────────────────────────────────────────

func TestCalcTxFee_HappyPath(t *testing.T) {
	// Two coinbase txs at different heights → distinct TxIDs → two UTXOs.
	cb1 := primitives.NewCoinbaseTx(1, 3_000_000, []byte{0x51}, 0)
	cb2 := primitives.NewCoinbaseTx(2, 7_000_000, []byte{0x52}, 0)
	us := populateUTXOs(t, cb1, cb2)

	feeTx := &primitives.Transaction{
		Version: 1,
		Inputs: []primitives.TxInput{
			{PreviousOutput: primitives.OutPoint{TxID: cb1.TxID(), Index: 0}, Sequence: 0xFFFFFFFF},
			{PreviousOutput: primitives.OutPoint{TxID: cb2.TxID(), Index: 0}, Sequence: 0xFFFFFFFF},
		},
		Outputs: []primitives.TxOutput{
			{Value: 9_500_000, ScriptPubKey: []byte{0x51}},
		},
	}

	fee, err := calcTxFee(feeTx, us)
	if err != nil {
		t.Fatalf("calcTxFee: %v", err)
	}
	// in = 3_000_000 + 7_000_000; out = 9_500_000; fee = 500_000
	if fee != 500_000 {
		t.Errorf("fee: got %d, want 500000", fee)
	}
}

func TestCalcTxFee_ZeroFee(t *testing.T) {
	cb := primitives.NewCoinbaseTx(1, 5_000_000, []byte{0x51}, 0)
	us := populateUTXOs(t, cb)

	feeTx := &primitives.Transaction{
		Version: 1,
		Inputs: []primitives.TxInput{{
			PreviousOutput: primitives.OutPoint{TxID: cb.TxID(), Index: 0},
			Sequence:       0xFFFFFFFF,
		}},
		Outputs: []primitives.TxOutput{{Value: 5_000_000, ScriptPubKey: []byte{0x51}}},
	}

	fee, err := calcTxFee(feeTx, us)
	if err != nil {
		t.Fatalf("calcTxFee: %v", err)
	}
	if fee != 0 {
		t.Errorf("fee: got %d, want 0", fee)
	}
}

func TestCalcTxFee_UTXONotFound(t *testing.T) {
	us := chain.NewUTXOSet(newTestDB())

	tx := &primitives.Transaction{
		Version: 1,
		Inputs: []primitives.TxInput{{
			PreviousOutput: primitives.OutPoint{TxID: [32]byte{0xDE, 0xAD}, Index: 0},
			Sequence:       0xFFFFFFFF,
		}},
		Outputs: []primitives.TxOutput{{Value: 1_000, ScriptPubKey: []byte{0x51}}},
	}

	_, err := calcTxFee(tx, us)
	if err == nil {
		t.Error("expected error when input UTXO is not found")
	}
}

func TestCalcTxFee_MultipleOutputs(t *testing.T) {
	cb := primitives.NewCoinbaseTx(1, 10_000_000, []byte{0x51}, 0)
	us := populateUTXOs(t, cb)

	feeTx := &primitives.Transaction{
		Version: 1,
		Inputs: []primitives.TxInput{{
			PreviousOutput: primitives.OutPoint{TxID: cb.TxID(), Index: 0},
			Sequence:       0xFFFFFFFF,
		}},
		Outputs: []primitives.TxOutput{
			{Value: 4_000_000, ScriptPubKey: []byte{0x51}},
			{Value: 4_000_000, ScriptPubKey: []byte{0x52}},
		},
	}

	fee, err := calcTxFee(feeTx, us)
	if err != nil {
		t.Fatalf("calcTxFee: %v", err)
	}
	// in = 10_000_000; out = 8_000_000; fee = 2_000_000
	if fee != 2_000_000 {
		t.Errorf("fee: got %d, want 2000000", fee)
	}
}

// ── NewBlockTemplate ──────────────────────────────────────────────────────────

func TestNewBlockTemplate_NilBlockchain(t *testing.T) {
	pool := mempool.NewTxPool()
	_, err := NewBlockTemplate(nil, pool, []byte{0x51}, 0)
	if err == nil {
		t.Error("expected error for nil blockchain")
	}
}

func TestNewBlockTemplate_EmptyCoinbaseScript(t *testing.T) {
	bc := newTestBlockchain(t)
	pool := mempool.NewTxPool()
	_, err := NewBlockTemplate(bc, pool, nil, 0)
	if err == nil {
		t.Error("expected error for nil coinbase script")
	}
	_, err = NewBlockTemplate(bc, pool, []byte{}, 0)
	if err == nil {
		t.Error("expected error for empty coinbase script")
	}
}

func TestNewBlockTemplate_EmptyMempool(t *testing.T) {
	bc := newTestBlockchain(t)
	pool := mempool.NewTxPool()

	tmpl, err := NewBlockTemplate(bc, pool, []byte{0x51}, 0)
	if err != nil {
		t.Fatalf("NewBlockTemplate: %v", err)
	}

	// Only the coinbase transaction.
	if len(tmpl.Txs) != 1 {
		t.Errorf("Txs count: got %d, want 1", len(tmpl.Txs))
	}
	if !tmpl.Txs[0].IsCoinbase() {
		t.Error("first tx must be coinbase")
	}
	// Height is genesis+1.
	if tmpl.Height != 1 {
		t.Errorf("Height: got %d, want 1", tmpl.Height)
	}
	// No fees → CoinbaseValue == subsidy at height 1.
	const wantSubsidy = 5_000_000_000 // InitialReward, no halving yet
	if tmpl.CoinbaseValue != wantSubsidy {
		t.Errorf("CoinbaseValue: got %d, want %d", tmpl.CoinbaseValue, wantSubsidy)
	}
	// PreviousHash must link to genesis (non-zero).
	if tmpl.Header.PreviousHash == ([32]byte{}) {
		t.Error("PreviousHash should not be zero")
	}
	// MerkleRoot must match the single coinbase tx.
	wantMerkle := primitives.CalcMerkleRoot(tmpl.Txs)
	if tmpl.Header.MerkleRoot != wantMerkle {
		t.Error("MerkleRoot does not match computed root")
	}
}

func TestNewBlockTemplate_IncludesConfirmedUTXOSpend(t *testing.T) {
	bc := newTestBlockchain(t)
	pool := mempool.NewTxPool()

	// Reconstruct the genesis coinbase TxID so we can spend it in the mempool.
	// GenesisBlock reads only immutable params fields, so it is safe to pass
	// the package-level var as a read-only reference here.
	genesis := chain.GenesisBlock(&chain.TestNetParams)
	genesisCbTxID := genesis.Txs[0].TxID()

	// Spend the genesis coinbase UTXO (value=5_000_000_000), leaving 1_000_000 as fee.
	// calcTxFee checks UTXO existence only, not coinbase maturity, so the tx is included.
	spendTx := &primitives.Transaction{
		Version: 1,
		Inputs: []primitives.TxInput{{
			PreviousOutput: primitives.OutPoint{TxID: genesisCbTxID, Index: 0},
			Sequence:       0xFFFFFFFF,
		}},
		Outputs: []primitives.TxOutput{{
			Value:        4_999_000_000,
			ScriptPubKey: []byte{0x51},
		}},
	}
	if err := pool.Add(spendTx); err != nil {
		t.Fatalf("pool.Add: %v", err)
	}

	tmpl, err := NewBlockTemplate(bc, pool, []byte{0x51}, 0)
	if err != nil {
		t.Fatalf("NewBlockTemplate: %v", err)
	}

	// Coinbase + spendTx.
	if len(tmpl.Txs) != 2 {
		t.Fatalf("Txs count: got %d, want 2", len(tmpl.Txs))
	}
	if !tmpl.Txs[0].IsCoinbase() {
		t.Error("first tx must be coinbase")
	}

	// CoinbaseValue = subsidy + fee = 5_000_000_000 + 1_000_000.
	const want = 5_000_000_000 + 1_000_000
	if tmpl.CoinbaseValue != want {
		t.Errorf("CoinbaseValue: got %d, want %d", tmpl.CoinbaseValue, want)
	}
}

func TestNewBlockTemplate_SkipsChaineUnconfirmed(t *testing.T) {
	bc := newTestBlockchain(t)
	pool := mempool.NewTxPool()

	// A tx whose input points to a non-existent UTXO (chained, unconfirmed).
	var ghostID [32]byte
	ghostID[0] = 0xFF
	chainedTx := &primitives.Transaction{
		Version: 1,
		Inputs: []primitives.TxInput{{
			PreviousOutput: primitives.OutPoint{TxID: ghostID, Index: 0},
			Sequence:       0xFFFFFFFF,
		}},
		Outputs: []primitives.TxOutput{{Value: 1_000_000, ScriptPubKey: []byte{0x51}}},
	}
	if err := pool.Add(chainedTx); err != nil {
		t.Fatalf("pool.Add: %v", err)
	}

	tmpl, err := NewBlockTemplate(bc, pool, []byte{0x51}, 0)
	if err != nil {
		t.Fatalf("NewBlockTemplate: %v", err)
	}

	// Chained tx skipped → only coinbase.
	if len(tmpl.Txs) != 1 {
		t.Errorf("Txs count: got %d, want 1 (chained tx should be skipped)", len(tmpl.Txs))
	}
	// No fees → CoinbaseValue == subsidy.
	if tmpl.CoinbaseValue != 5_000_000_000 {
		t.Errorf("CoinbaseValue: got %d, want 5000000000", tmpl.CoinbaseValue)
	}
}

func TestNewBlockTemplate_ExtraNonceChangesMerkleRoot(t *testing.T) {
	bc := newTestBlockchain(t)
	pool := mempool.NewTxPool()
	script := []byte{0x51}

	tmpl0, err := NewBlockTemplate(bc, pool, script, 0)
	if err != nil {
		t.Fatalf("NewBlockTemplate(extraNonce=0): %v", err)
	}
	tmpl1, err := NewBlockTemplate(bc, pool, script, 1)
	if err != nil {
		t.Fatalf("NewBlockTemplate(extraNonce=1): %v", err)
	}

	// Different extraNonce → different coinbase serialisation → different TxID → different Merkle root.
	if tmpl0.Header.MerkleRoot == tmpl1.Header.MerkleRoot {
		t.Error("different extraNonce values should produce different merkle roots")
	}
}
