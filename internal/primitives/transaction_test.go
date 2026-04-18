package primitives

import (
	"bytes"
	"testing"
)

func TestTransactionSerializeDeserialize(t *testing.T) {
	tx := &Transaction{
		Version: 1,
		Inputs: []TxInput{
			{
				PreviousOutput: OutPoint{
					TxID:  [32]byte{1, 2, 3},
					Index: 0,
				},
				ScriptSig: []byte{0x01, 0x02, 0x03},
				Sequence:  0xFFFFFFFF,
			},
		},
		Outputs: []TxOutput{
			{
				Value:        5_000_000_000,
				ScriptPubKey: []byte{0x76, 0xa9, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x88, 0xac},
			},
		},
		LockTime: 0,
	}

	data := tx.Serialize()
	if len(data) == 0 {
		t.Fatal("Serialize returned empty data")
	}

	deserialized, n, err := DeserializeTx(data)
	if err != nil {
		t.Fatalf("DeserializeTx error: %v", err)
	}
	if n != len(data) {
		t.Errorf("DeserializeTx consumed %d bytes, expected %d", n, len(data))
	}

	// Verify fields match
	if deserialized.Version != tx.Version {
		t.Errorf("Version mismatch: %d vs %d", deserialized.Version, tx.Version)
	}
	if len(deserialized.Inputs) != len(tx.Inputs) {
		t.Errorf("Input count mismatch: %d vs %d", len(deserialized.Inputs), len(tx.Inputs))
	}
	if len(deserialized.Outputs) != len(tx.Outputs) {
		t.Errorf("Output count mismatch: %d vs %d", len(deserialized.Outputs), len(tx.Outputs))
	}
	if deserialized.Outputs[0].Value != tx.Outputs[0].Value {
		t.Errorf("Output value mismatch: %d vs %d", deserialized.Outputs[0].Value, tx.Outputs[0].Value)
	}
}

func TestCoinbaseIsCoinbase(t *testing.T) {
	tx := &Transaction{
		Version: 1,
		Inputs: []TxInput{
			{
				PreviousOutput: OutPoint{
					TxID:  [32]byte{}, // all zeros
					Index: 0xFFFFFFFF,
				},
				ScriptSig: []byte("genesis"),
				Sequence:  0xFFFFFFFF,
			},
		},
		Outputs: []TxOutput{
			{Value: 5_000_000_000, ScriptPubKey: []byte{0xac}},
		},
	}

	if !tx.IsCoinbase() {
		t.Error("Expected IsCoinbase() == true for coinbase transaction")
	}
}

func TestNonCoinbaseIsNotCoinbase(t *testing.T) {
	tx := &Transaction{
		Version: 1,
		Inputs: []TxInput{
			{
				PreviousOutput: OutPoint{
					TxID:  [32]byte{1, 2, 3},
					Index: 0,
				},
				ScriptSig: []byte{0x01},
				Sequence:  0xFFFFFFFF,
			},
		},
		Outputs: []TxOutput{{Value: 1000, ScriptPubKey: []byte{0xac}}},
	}

	if tx.IsCoinbase() {
		t.Error("Expected IsCoinbase() == false for non-coinbase transaction")
	}
}

func TestTxIDDeterministic(t *testing.T) {
	tx := &Transaction{
		Version: 1,
		Inputs: []TxInput{
			{
				PreviousOutput: OutPoint{Index: 0},
				ScriptSig:      []byte{0xab},
				Sequence:       0xFFFFFFFF,
			},
		},
		Outputs: []TxOutput{{Value: 1000, ScriptPubKey: []byte{0x01}}},
	}

	id1 := tx.TxID()
	id2 := tx.TxID()
	if id1 != id2 {
		t.Errorf("TxID not deterministic: %x vs %x", id1, id2)
	}
}

func TestVarIntEncoding(t *testing.T) {
	cases := []uint64{0, 1, 0xFC, 0xFD, 0xFFFF, 0x10000, 0xFFFFFFFF, 0x100000000}
	for _, v := range cases {
		encoded := encodeVarInt(v)
		decoded, n, err := DecodeVarInt(encoded)
		if err != nil {
			t.Errorf("DecodeVarInt(%d) error: %v", v, err)
			continue
		}
		if decoded != v {
			t.Errorf("VarInt round trip failed for %d: got %d", v, decoded)
		}
		if n != len(encoded) {
			t.Errorf("VarInt bytes consumed: expected %d, got %d", len(encoded), n)
		}
	}
}

func TestSerializeTransactionsRoundTrip(t *testing.T) {
	txs := []*Transaction{
		{
			Version: 1,
			Inputs:  []TxInput{{PreviousOutput: OutPoint{Index: 0xFFFFFFFF}, ScriptSig: []byte("cb"), Sequence: 0xFFFFFFFF}},
			Outputs: []TxOutput{{Value: 100, ScriptPubKey: []byte{0x51}}},
		},
		{
			Version: 1,
			Inputs:  []TxInput{{PreviousOutput: OutPoint{TxID: [32]byte{5}, Index: 1}, ScriptSig: []byte{0x02}, Sequence: 0}},
			Outputs: []TxOutput{{Value: 50, ScriptPubKey: []byte{0x52}}},
		},
	}

	data := SerializeTransactions(txs)
	decoded, err := DeserializeTransactions(data)
	if err != nil {
		t.Fatalf("DeserializeTransactions error: %v", err)
	}
	if len(decoded) != len(txs) {
		t.Fatalf("Transaction count mismatch: got %d, want %d", len(decoded), len(txs))
	}
	for i, tx := range txs {
		orig := tx.Serialize()
		got := decoded[i].Serialize()
		if !bytes.Equal(orig, got) {
			t.Errorf("Transaction %d serialization mismatch", i)
		}
	}
}
