package chain

import (
	"encoding/binary"
	"testing"

	"github.com/malairt/malairt/internal/crypto"
	"github.com/malairt/malairt/internal/primitives"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// newSpendTx builds a minimal transaction that spends one UTXO locked by scriptPubKey.
func newSpendTx(scriptPubKey []byte) *primitives.Transaction {
	return &primitives.Transaction{
		Version: 1,
		Inputs: []primitives.TxInput{{
			PreviousOutput: primitives.OutPoint{TxID: [32]byte{0xAA}, Index: 0},
			Sequence:       0xFFFFFFFF,
		}},
		Outputs: []primitives.TxOutput{{
			Value:        1_000_000,
			ScriptPubKey: scriptPubKey,
		}},
		LockTime: 0,
	}
}

// buildP2PKHScriptSig assembles <push sig+hashType> <push pubkey>.
func buildP2PKHScriptSig(sig, pubKey []byte) []byte {
	var s []byte
	s = append(s, byte(len(sig)))
	s = append(s, sig...)
	s = append(s, byte(len(pubKey)))
	s = append(s, pubKey...)
	return s
}

// signInput signs tx input inputIdx and returns scriptSig ready for that input.
func signInput(t *testing.T, privKey, pubKey []byte, tx *primitives.Transaction, inputIdx int, scriptPubKey []byte) []byte {
	t.Helper()
	sigHash := calcSigHash(tx, inputIdx, scriptPubKey)
	derSig, err := crypto.Sign(privKey, sigHash[:])
	if err != nil {
		t.Fatal(err)
	}
	return buildP2PKHScriptSig(append(derSig, sigHashAll), pubKey)
}

// ── ExecuteScript tests ───────────────────────────────────────────────────────

func TestExecuteScript_P2PKH_Valid(t *testing.T) {
	privKey, pubKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	scriptPubKey := primitives.P2PKHScript(crypto.Hash160(pubKey))
	tx := newSpendTx(scriptPubKey)
	tx.Inputs[0].ScriptSig = signInput(t, privKey, pubKey, tx, 0, scriptPubKey)

	if err := ExecuteScript(tx.Inputs[0].ScriptSig, scriptPubKey, tx, 0); err != nil {
		t.Errorf("valid P2PKH: unexpected error: %v", err)
	}
}

func TestExecuteScript_P2PKH_WrongPubkey(t *testing.T) {
	privKey1, pubKey1, _ := crypto.GenerateKeyPair()
	_, pubKey2, _ := crypto.GenerateKeyPair()

	// Output locked to pubKey1's hash; scriptSig provides pubKey2 (wrong key)
	scriptPubKey := primitives.P2PKHScript(crypto.Hash160(pubKey1))
	tx := newSpendTx(scriptPubKey)

	sigHash := calcSigHash(tx, 0, scriptPubKey)
	derSig, _ := crypto.Sign(privKey1, sigHash[:])
	tx.Inputs[0].ScriptSig = buildP2PKHScriptSig(append(derSig, sigHashAll), pubKey2)

	if err := ExecuteScript(tx.Inputs[0].ScriptSig, scriptPubKey, tx, 0); err == nil {
		t.Error("expected error for wrong pubkey, got nil")
	}
}

func TestExecuteScript_P2PKH_WrongSignature(t *testing.T) {
	privKey, pubKey, _ := crypto.GenerateKeyPair()
	scriptPubKey := primitives.P2PKHScript(crypto.Hash160(pubKey))
	tx := newSpendTx(scriptPubKey)

	// Sign a different hash — signature will not match the actual transaction
	wrongHash := [32]byte{0xFF}
	derSig, _ := crypto.Sign(privKey, wrongHash[:])
	tx.Inputs[0].ScriptSig = buildP2PKHScriptSig(append(derSig, sigHashAll), pubKey)

	if err := ExecuteScript(tx.Inputs[0].ScriptSig, scriptPubKey, tx, 0); err == nil {
		t.Error("expected error for wrong signature, got nil")
	}
}

func TestExecuteScript_P2PKH_SigCoversOutputs(t *testing.T) {
	privKey, pubKey, _ := crypto.GenerateKeyPair()
	scriptPubKey := primitives.P2PKHScript(crypto.Hash160(pubKey))

	// Sign a transaction with one output
	tx := newSpendTx(scriptPubKey)
	tx.Inputs[0].ScriptSig = signInput(t, privKey, pubKey, tx, 0, scriptPubKey)

	// Tamper with the output value — signature should now be invalid
	tx.Outputs[0].Value = 999_999_999
	if err := ExecuteScript(tx.Inputs[0].ScriptSig, scriptPubKey, tx, 0); err == nil {
		t.Error("expected error after tampering with output value, got nil")
	}
}

func TestExecuteScript_NonP2PKH_Permissive(t *testing.T) {
	nonP2PKH := []byte{0x51} // OP_1
	tx := newSpendTx(nonP2PKH)
	if err := ExecuteScript([]byte{}, nonP2PKH, tx, 0); err != nil {
		t.Errorf("non-P2PKH should pass permissively, got: %v", err)
	}
}

// ── calcSigHash tests ─────────────────────────────────────────────────────────

func TestCalcSigHash_DifferentInputsDifferentHashes(t *testing.T) {
	_, pubKey, _ := crypto.GenerateKeyPair()
	scriptPubKey := primitives.P2PKHScript(crypto.Hash160(pubKey))

	tx := &primitives.Transaction{
		Version: 1,
		Inputs: []primitives.TxInput{
			{PreviousOutput: primitives.OutPoint{TxID: [32]byte{0x01}, Index: 0}, Sequence: 0xFFFFFFFF},
			{PreviousOutput: primitives.OutPoint{TxID: [32]byte{0x02}, Index: 0}, Sequence: 0xFFFFFFFF},
		},
		Outputs: []primitives.TxOutput{{Value: 500_000, ScriptPubKey: scriptPubKey}},
	}

	h0 := calcSigHash(tx, 0, scriptPubKey)
	h1 := calcSigHash(tx, 1, scriptPubKey)

	if h0 == h1 {
		t.Error("sigHash for input 0 and input 1 must be different")
	}
}

func TestCalcSigHash_Deterministic(t *testing.T) {
	_, pubKey, _ := crypto.GenerateKeyPair()
	scriptPubKey := primitives.P2PKHScript(crypto.Hash160(pubKey))
	tx := newSpendTx(scriptPubKey)

	h1 := calcSigHash(tx, 0, scriptPubKey)
	h2 := calcSigHash(tx, 0, scriptPubKey)

	if h1 != h2 {
		t.Error("calcSigHash must be deterministic")
	}
}

// ── readDataPush tests ────────────────────────────────────────────────────────

func TestReadDataPush_Direct(t *testing.T) {
	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	script := append([]byte{byte(len(payload))}, payload...)

	data, consumed, err := readDataPush(script, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1+len(payload) {
		t.Errorf("consumed: got %d, want %d", consumed, 1+len(payload))
	}
	if string(data) != string(payload) {
		t.Errorf("data: got %x, want %x", data, payload)
	}
}

func TestReadDataPush_PUSHDATA1(t *testing.T) {
	payload := make([]byte, 100)
	for i := range payload {
		payload[i] = byte(i)
	}
	script := []byte{0x4c, byte(len(payload))}
	script = append(script, payload...)

	data, consumed, err := readDataPush(script, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 2+len(payload) {
		t.Errorf("consumed: got %d, want %d", consumed, 2+len(payload))
	}
	if string(data) != string(payload) {
		t.Errorf("data mismatch")
	}
}

func TestReadDataPush_PUSHDATA2(t *testing.T) {
	payload := make([]byte, 300)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	var lenBytes [2]byte
	binary.LittleEndian.PutUint16(lenBytes[:], uint16(len(payload)))
	script := append([]byte{0x4d}, lenBytes[:]...)
	script = append(script, payload...)

	data, consumed, err := readDataPush(script, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 3+len(payload) {
		t.Errorf("consumed: got %d, want %d", consumed, 3+len(payload))
	}
	if len(data) != len(payload) {
		t.Errorf("data length: got %d, want %d", len(data), len(payload))
	}
}

func TestReadDataPush_Errors(t *testing.T) {
	tests := []struct {
		name   string
		script []byte
	}{
		{"empty", []byte{}},
		{"truncated direct push", []byte{0x05, 0x01}},            // says 5 bytes but only 1
		{"pushdata1 missing length", []byte{0x4c}},               // OP_PUSHDATA1 with no length
		{"pushdata1 truncated data", []byte{0x4c, 0x05, 0x01}},   // says 5 bytes but only 1
		{"unsupported opcode", []byte{0x00}},                     // OP_0 is not a data push
	}

	for _, tc := range tests {
		_, _, err := readDataPush(tc.script, 0)
		if err == nil {
			t.Errorf("%s: expected error, got nil", tc.name)
		}
	}
}
