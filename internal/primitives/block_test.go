package primitives

import (
	"testing"
)

func TestBlockHeaderSerializeSize(t *testing.T) {
	h := &BlockHeader{
		Version:      1,
		PreviousHash: [32]byte{},
		MerkleRoot:   [32]byte{},
		Timestamp:    1_704_067_200,
		Bits:         0x207fffff,
		Nonce:        42,
		Height:       0,
	}

	data := h.Serialize()
	if len(data) != 96 {
		t.Errorf("BlockHeader serialization: expected 96 bytes, got %d", len(data))
	}
}

func TestBlockHeaderSerializeDeserialize(t *testing.T) {
	orig := &BlockHeader{
		Version:      1,
		PreviousHash: [32]byte{1, 2, 3},
		MerkleRoot:   [32]byte{4, 5, 6},
		Timestamp:    1_704_067_200,
		Bits:         0x207fffff,
		Nonce:        999999,
		Height:       12345,
	}

	data := orig.Serialize()
	decoded, err := DeserializeBlockHeader(data)
	if err != nil {
		t.Fatalf("DeserializeBlockHeader error: %v", err)
	}

	if decoded.Version != orig.Version {
		t.Errorf("Version: %d vs %d", decoded.Version, orig.Version)
	}
	if decoded.PreviousHash != orig.PreviousHash {
		t.Errorf("PreviousHash mismatch")
	}
	if decoded.MerkleRoot != orig.MerkleRoot {
		t.Errorf("MerkleRoot mismatch")
	}
	if decoded.Timestamp != orig.Timestamp {
		t.Errorf("Timestamp: %d vs %d", decoded.Timestamp, orig.Timestamp)
	}
	if decoded.Bits != orig.Bits {
		t.Errorf("Bits: 0x%08x vs 0x%08x", decoded.Bits, orig.Bits)
	}
	if decoded.Nonce != orig.Nonce {
		t.Errorf("Nonce: %d vs %d", decoded.Nonce, orig.Nonce)
	}
	if decoded.Height != orig.Height {
		t.Errorf("Height: %d vs %d", decoded.Height, orig.Height)
	}
}

func TestBlockHeaderHash(t *testing.T) {
	h := &BlockHeader{
		Version:      1,
		PreviousHash: [32]byte{},
		MerkleRoot:   [32]byte{},
		Timestamp:    1_704_067_200,
		Bits:         0x207fffff,
		Nonce:        0,
		Height:       0,
	}

	hash1 := h.Hash()
	hash2 := h.Hash()

	if hash1 != hash2 {
		t.Errorf("BlockHeader.Hash() not deterministic: %x vs %x", hash1, hash2)
	}

	// Hash should be non-zero
	var zero [32]byte
	if hash1 == zero {
		t.Errorf("BlockHeader.Hash() returned all-zeros")
	}
}

func TestCalcMerkleRoot(t *testing.T) {
	// Empty transaction list
	empty := CalcMerkleRoot([]*Transaction{})
	var zeroHash [32]byte
	if empty != zeroHash {
		t.Errorf("CalcMerkleRoot([]) should return zero hash, got %x", empty)
	}

	// Single transaction
	tx1 := &Transaction{
		Version:  1,
		Inputs:   []TxInput{{PreviousOutput: OutPoint{Index: 0xFFFFFFFF}, ScriptSig: []byte("a"), Sequence: 0xFFFFFFFF}},
		Outputs:  []TxOutput{{Value: 100, ScriptPubKey: []byte{0x51}}},
		LockTime: 0,
	}
	root1 := CalcMerkleRoot([]*Transaction{tx1})
	expected1 := tx1.TxID()
	if root1 != expected1 {
		t.Errorf("Single-tx merkle root should equal txid: got %x, want %x", root1, expected1)
	}

	// Two transactions — root should be deterministic
	tx2 := &Transaction{
		Version:  1,
		Inputs:   []TxInput{{PreviousOutput: OutPoint{TxID: [32]byte{1}, Index: 0}, ScriptSig: []byte("b"), Sequence: 0}},
		Outputs:  []TxOutput{{Value: 50, ScriptPubKey: []byte{0x52}}},
		LockTime: 0,
	}
	root2a := CalcMerkleRoot([]*Transaction{tx1, tx2})
	root2b := CalcMerkleRoot([]*Transaction{tx1, tx2})
	if root2a != root2b {
		t.Errorf("CalcMerkleRoot not deterministic for two txs")
	}

	// Different order should produce different root
	root2c := CalcMerkleRoot([]*Transaction{tx2, tx1})
	if root2a == root2c {
		t.Errorf("Different tx order should produce different merkle root")
	}
}

func TestNewCoinbaseTx(t *testing.T) {
	scriptPubKey := []byte{0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0xac}
	tx := NewCoinbaseTx(100, 5_000_000_000, scriptPubKey, 0)

	if !tx.IsCoinbase() {
		t.Error("NewCoinbaseTx should produce a coinbase transaction")
	}
	if tx.Outputs[0].Value != 5_000_000_000 {
		t.Errorf("Coinbase value: got %d, want 5000000000", tx.Outputs[0].Value)
	}
	if tx.Inputs[0].Sequence != 0xFFFFFFFF {
		t.Errorf("Coinbase sequence: got %d, want 0xFFFFFFFF", tx.Inputs[0].Sequence)
	}
}

func TestTransactionWeight_EmptyWitness(t *testing.T) {
	// A tx with no witness data still pays the segwit marker+flag+one-varint-per-input
	// overhead in Serialize(). BaseSize is the legacy length (no marker, no witness).
	tx := &Transaction{
		Version: 1,
		Inputs: []TxInput{{
			PreviousOutput: OutPoint{TxID: [32]byte{1}, Index: 0},
			ScriptSig:      []byte{0x51},
			Sequence:       0xFFFFFFFF,
		}},
		Outputs:  []TxOutput{{Value: 100, ScriptPubKey: []byte{0x51}}},
		LockTime: 0,
	}
	base := tx.BaseSize()
	total := tx.TotalSize()
	if total <= base {
		t.Errorf("TotalSize %d must exceed BaseSize %d (marker+flag+witness counts)", total, base)
	}
	if diff := total - base; diff != 3 {
		// 1 marker + 1 flag + 1 zero-item varint per input = 3 bytes for 1 input.
		t.Errorf("segwit overhead: got %d bytes, want 3", diff)
	}
	if got, want := tx.Weight(), base*WitnessScaleFactor+(total-base); got != want {
		t.Errorf("Weight: got %d, want %d", got, want)
	}
}

func TestTransactionWeight_NonEmptyWitness(t *testing.T) {
	tx := &Transaction{
		Version: 1,
		Inputs: []TxInput{{
			PreviousOutput: OutPoint{TxID: [32]byte{1}, Index: 0},
			ScriptSig:      nil,
			Sequence:       0xFFFFFFFF,
			Witness:        [][]byte{{0xAA, 0xBB, 0xCC}, {0xDD}}, // two items
		}},
		Outputs:  []TxOutput{{Value: 100, ScriptPubKey: []byte{0x51}}},
		LockTime: 0,
	}
	base := tx.BaseSize()
	total := tx.TotalSize()
	// Witness items contribute 1 WU/byte while base bytes contribute 4 WU/byte.
	want := base*WitnessScaleFactor + (total - base)
	if got := tx.Weight(); got != want {
		t.Errorf("Weight: got %d, want %d (base=%d total=%d)", got, want, base, total)
	}
	// Round-trip through Deserialize preserves the witness stack.
	decoded, _, err := DeserializeTx(tx.Serialize())
	if err != nil {
		t.Fatalf("DeserializeTx: %v", err)
	}
	if len(decoded.Inputs[0].Witness) != 2 ||
		string(decoded.Inputs[0].Witness[0]) != string(tx.Inputs[0].Witness[0]) ||
		string(decoded.Inputs[0].Witness[1]) != string(tx.Inputs[0].Witness[1]) {
		t.Errorf("witness round-trip mismatch: %x", decoded.Inputs[0].Witness)
	}
	// TxID must ignore the witness stack — that's the malleability fix.
	tx2 := *tx
	tx2.Inputs = []TxInput{tx.Inputs[0]}
	tx2.Inputs[0].Witness = [][]byte{{0xFF}} // different witness
	if tx2.TxID() != tx.TxID() {
		t.Error("TxID must not depend on witness data")
	}
	if tx2.WTxID() == tx.WTxID() {
		t.Error("WTxID must change when witness data changes")
	}
}

func TestBlockWeight(t *testing.T) {
	// Two txs: one without witness data, one with.
	txA := &Transaction{
		Version:  1,
		Inputs:   []TxInput{{PreviousOutput: OutPoint{Index: 0xFFFFFFFF}, ScriptSig: []byte("c"), Sequence: 0xFFFFFFFF}},
		Outputs:  []TxOutput{{Value: 1, ScriptPubKey: []byte{0x51}}},
		LockTime: 0,
	}
	txB := &Transaction{
		Version: 1,
		Inputs: []TxInput{{
			PreviousOutput: OutPoint{TxID: [32]byte{1}, Index: 0},
			Sequence:       0xFFFFFFFF,
			Witness:        [][]byte{{0x11, 0x22, 0x33, 0x44}},
		}},
		Outputs:  []TxOutput{{Value: 2, ScriptPubKey: []byte{0x52}}},
		LockTime: 0,
	}
	block := &Block{
		Header: BlockHeader{Version: 1},
		Txs:    []*Transaction{txA, txB},
	}

	base := block.BaseSize()
	total := block.TotalSize()
	if base >= total {
		t.Errorf("expected BaseSize (%d) < TotalSize (%d) when witness data present", base, total)
	}
	want := base*WitnessScaleFactor + (total - base)
	if got := block.Weight(); got != want {
		t.Errorf("Block.Weight: got %d, want %d (base=%d total=%d)", got, want, base, total)
	}
}

func TestBlockHashDifferentNonces(t *testing.T) {
	h1 := &BlockHeader{
		Version: 1, Bits: 0x207fffff, Timestamp: 1_704_067_200, Nonce: 0,
	}
	h2 := &BlockHeader{
		Version: 1, Bits: 0x207fffff, Timestamp: 1_704_067_200, Nonce: 1,
	}
	if h1.Hash() == h2.Hash() {
		t.Error("Different nonces should produce different hashes")
	}
}
