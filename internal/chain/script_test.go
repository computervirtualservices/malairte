package chain

import (
	"encoding/binary"
	"testing"

	"github.com/computervirtualservices/malairte/internal/crypto"
	"github.com/computervirtualservices/malairte/internal/primitives"
)

// testChainID is an arbitrary chain-id used throughout these tests. The
// specific value doesn't matter for correctness as long as signer and verifier
// agree on it — but reusing the same value across tests makes failures easier
// to diagnose.
const testChainID uint32 = 0x4d4c5254 // "MLRT"

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
	sigHash := calcSigHash(tx, inputIdx, scriptPubKey, testChainID)
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

	if err := ExecuteScript(tx.Inputs[0].ScriptSig, scriptPubKey, tx, 0, 0, nil, nil, testChainID); err != nil {
		t.Errorf("valid P2PKH: unexpected error: %v", err)
	}
}

func TestExecuteScript_P2PKH_WrongPubkey(t *testing.T) {
	privKey1, pubKey1, _ := crypto.GenerateKeyPair()
	_, pubKey2, _ := crypto.GenerateKeyPair()

	// Output locked to pubKey1's hash; scriptSig provides pubKey2 (wrong key)
	scriptPubKey := primitives.P2PKHScript(crypto.Hash160(pubKey1))
	tx := newSpendTx(scriptPubKey)

	sigHash := calcSigHash(tx, 0, scriptPubKey, testChainID)
	derSig, _ := crypto.Sign(privKey1, sigHash[:])
	tx.Inputs[0].ScriptSig = buildP2PKHScriptSig(append(derSig, sigHashAll), pubKey2)

	if err := ExecuteScript(tx.Inputs[0].ScriptSig, scriptPubKey, tx, 0, 0, nil, nil, testChainID); err == nil {
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

	if err := ExecuteScript(tx.Inputs[0].ScriptSig, scriptPubKey, tx, 0, 0, nil, nil, testChainID); err == nil {
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
	if err := ExecuteScript(tx.Inputs[0].ScriptSig, scriptPubKey, tx, 0, 0, nil, nil, testChainID); err == nil {
		t.Error("expected error after tampering with output value, got nil")
	}
}

func TestExecuteScript_NonP2PKH_Permissive(t *testing.T) {
	nonP2PKH := []byte{0x51} // OP_1
	tx := newSpendTx(nonP2PKH)
	if err := ExecuteScript([]byte{}, nonP2PKH, tx, 0, 0, nil, nil, testChainID); err != nil {
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

	h0 := calcSigHash(tx, 0, scriptPubKey, testChainID)
	h1 := calcSigHash(tx, 1, scriptPubKey, testChainID)

	if h0 == h1 {
		t.Error("sigHash for input 0 and input 1 must be different")
	}
}

func TestCalcSigHash_Deterministic(t *testing.T) {
	_, pubKey, _ := crypto.GenerateKeyPair()
	scriptPubKey := primitives.P2PKHScript(crypto.Hash160(pubKey))
	tx := newSpendTx(scriptPubKey)

	h1 := calcSigHash(tx, 0, scriptPubKey, testChainID)
	h2 := calcSigHash(tx, 0, scriptPubKey, testChainID)

	if h1 != h2 {
		t.Error("calcSigHash must be deterministic")
	}
}

func TestCalcSigHash_ChainIDBindsSignature(t *testing.T) {
	// A signature valid on chain A must not verify on chain B. We sign under
	// the mainnet chain id, then try to verify under testnet's chain id.
	privKey, pubKey, _ := crypto.GenerateKeyPair()
	scriptPubKey := primitives.P2PKHScript(crypto.Hash160(pubKey))
	tx := newSpendTx(scriptPubKey)

	mainnetID := uint32(0x4d4c5254) // "MLRT"
	testnetID := uint32(0x4d4c7274) // "MLrt"

	// Sign under mainnet chain id.
	sigHash := calcSigHash(tx, 0, scriptPubKey, mainnetID)
	derSig, err := crypto.Sign(privKey, sigHash[:])
	if err != nil {
		t.Fatal(err)
	}
	tx.Inputs[0].ScriptSig = buildP2PKHScriptSig(append(derSig, sigHashAll), pubKey)

	// Verify under mainnet: must succeed.
	if err := ExecuteScript(tx.Inputs[0].ScriptSig, scriptPubKey, tx, 0, 0, nil, nil, mainnetID); err != nil {
		t.Errorf("mainnet sig on mainnet should verify: %v", err)
	}
	// Verify under testnet: must fail (cross-chain replay blocked).
	if err := ExecuteScript(tx.Inputs[0].ScriptSig, scriptPubKey, tx, 0, 0, nil, nil, testnetID); err == nil {
		t.Error("mainnet sig should NOT verify on testnet (replay protection broken)")
	}
}

// ── P2WPKH (SegWit v0) tests ──────────────────────────────────────────────────

// signP2WPKH signs input inputIdx under BIP-143 and returns the 2-item witness
// stack [sig+hashtype, pubkey] ready to attach to the input.
func signP2WPKH(t *testing.T, privKey, pubKey []byte, tx *primitives.Transaction, inputIdx int, amount int64) [][]byte {
	t.Helper()
	pkh := crypto.Hash160(pubKey)
	scriptCode := primitives.P2PKHScript(pkh)
	sigHash := CalcSigHashWitnessV0(tx, inputIdx, scriptCode, amount, testChainID)
	derSig, err := crypto.Sign(privKey, sigHash[:])
	if err != nil {
		t.Fatal(err)
	}
	sigWithType := append(derSig, sigHashAll)
	return [][]byte{sigWithType, pubKey}
}

func TestExecuteScript_P2WPKH_Valid(t *testing.T) {
	privKey, pubKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pkh := crypto.Hash160(pubKey)
	scriptPubKey := primitives.P2WPKHScript(pkh)

	tx := &primitives.Transaction{
		Version: 1,
		Inputs: []primitives.TxInput{{
			PreviousOutput: primitives.OutPoint{TxID: [32]byte{0xAA}, Index: 0},
			Sequence:       0xFFFFFFFF,
		}},
		Outputs: []primitives.TxOutput{{
			Value:        900_000,
			ScriptPubKey: primitives.P2PKHScript([20]byte{0xBB}),
		}},
		LockTime: 0,
	}
	amount := int64(1_000_000)
	tx.Inputs[0].Witness = signP2WPKH(t, privKey, pubKey, tx, 0, amount)

	if err := ExecuteScript(nil, scriptPubKey, tx, 0, amount, nil, nil, testChainID); err != nil {
		t.Errorf("valid P2WPKH: unexpected error: %v", err)
	}
}

func TestExecuteScript_P2WPKH_RejectsNonEmptyScriptSig(t *testing.T) {
	_, pubKey, _ := crypto.GenerateKeyPair()
	pkh := crypto.Hash160(pubKey)
	scriptPubKey := primitives.P2WPKHScript(pkh)
	tx := &primitives.Transaction{
		Version:  1,
		Inputs:   []primitives.TxInput{{Sequence: 0xFFFFFFFF, ScriptSig: []byte{0x01}}},
		Outputs:  []primitives.TxOutput{{Value: 1, ScriptPubKey: []byte{0x51}}},
		LockTime: 0,
	}
	if err := ExecuteScript(tx.Inputs[0].ScriptSig, scriptPubKey, tx, 0, 1, nil, nil, testChainID); err == nil {
		t.Error("P2WPKH must reject non-empty scriptSig")
	}
}

func TestExecuteScript_P2WPKH_RejectsWrongPubkey(t *testing.T) {
	privKey1, pubKey1, _ := crypto.GenerateKeyPair()
	_, pubKey2, _ := crypto.GenerateKeyPair()
	// Output bound to pubKey1's hash
	scriptPubKey := primitives.P2WPKHScript(crypto.Hash160(pubKey1))
	tx := &primitives.Transaction{
		Version:  1,
		Inputs:   []primitives.TxInput{{Sequence: 0xFFFFFFFF}},
		Outputs:  []primitives.TxOutput{{Value: 1, ScriptPubKey: []byte{0x51}}},
		LockTime: 0,
	}
	// Sign with privKey1 but put pubKey2 in the witness
	pkh := crypto.Hash160(pubKey1)
	scriptCode := primitives.P2PKHScript(pkh)
	sigHash := CalcSigHashWitnessV0(tx, 0, scriptCode, 1, testChainID)
	derSig, _ := crypto.Sign(privKey1, sigHash[:])
	tx.Inputs[0].Witness = [][]byte{append(derSig, sigHashAll), pubKey2}

	if err := ExecuteScript(nil, scriptPubKey, tx, 0, 1, nil, nil, testChainID); err == nil {
		t.Error("P2WPKH must reject witness pubkey that doesn't match scriptPubKey hash")
	}
}

func TestExecuteScript_P2WPKH_AmountCoveredBySig(t *testing.T) {
	// BIP-143 mixes the amount into the preimage. If the verifier uses a
	// different amount than the signer did, the signature must fail.
	privKey, pubKey, _ := crypto.GenerateKeyPair()
	pkh := crypto.Hash160(pubKey)
	scriptPubKey := primitives.P2WPKHScript(pkh)
	tx := &primitives.Transaction{
		Version:  1,
		Inputs:   []primitives.TxInput{{Sequence: 0xFFFFFFFF}},
		Outputs:  []primitives.TxOutput{{Value: 1, ScriptPubKey: []byte{0x51}}},
		LockTime: 0,
	}
	tx.Inputs[0].Witness = signP2WPKH(t, privKey, pubKey, tx, 0, 1_000_000)

	// Same witness, verify with amount=2_000_000 → must fail.
	if err := ExecuteScript(nil, scriptPubKey, tx, 0, 2_000_000, nil, nil, testChainID); err == nil {
		t.Error("P2WPKH must reject when verified amount differs from signed amount")
	}
}

func TestExecuteScript_P2WPKH_WrongWitnessArity(t *testing.T) {
	_, pubKey, _ := crypto.GenerateKeyPair()
	scriptPubKey := primitives.P2WPKHScript(crypto.Hash160(pubKey))
	tx := &primitives.Transaction{
		Version: 1,
		Inputs: []primitives.TxInput{{
			Sequence: 0xFFFFFFFF,
			Witness:  [][]byte{{0x01}, {0x02}, {0x03}}, // 3 items, not 2
		}},
		Outputs:  []primitives.TxOutput{{Value: 1, ScriptPubKey: []byte{0x51}}},
		LockTime: 0,
	}
	if err := ExecuteScript(nil, scriptPubKey, tx, 0, 1, nil, nil, testChainID); err == nil {
		t.Error("P2WPKH must reject witness with wrong item count")
	}
}

// ── P2TR (Taproot, BIP-341) key-path tests ────────────────────────────────────

// buildP2TRTx constructs a minimal transaction that spends one P2TR output.
// Returns the tx plus the prevout vectors ValidateTx would supply.
func buildP2TRTx(t *testing.T, xonly []byte, amount int64) (*primitives.Transaction, [][]byte, []int64) {
	t.Helper()
	var key [32]byte
	copy(key[:], xonly)
	spkIn := primitives.P2TRScript(key)
	tx := &primitives.Transaction{
		Version: 2,
		Inputs: []primitives.TxInput{{
			PreviousOutput: primitives.OutPoint{TxID: [32]byte{0xCC}, Index: 0},
			Sequence:       0xFFFFFFFF,
		}},
		Outputs: []primitives.TxOutput{{
			Value:        amount - 1_000,
			ScriptPubKey: primitives.P2PKHScript([20]byte{0xEE}),
		}},
		LockTime: 0,
	}
	return tx, [][]byte{spkIn}, []int64{amount}
}

func TestExecuteScript_P2TR_KeyPath_Valid(t *testing.T) {
	priv, pub, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	xonly, err := crypto.XOnlyPubKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	amount := int64(500_000)
	tx, prevScripts, prevAmounts := buildP2TRTx(t, xonly, amount)

	sigHash, err := CalcTaprootKeySpendSigHash(tx, 0, prevScripts, prevAmounts, sigHashDefault, testChainID)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := crypto.SchnorrSign(priv, sigHash[:])
	if err != nil {
		t.Fatal(err)
	}
	tx.Inputs[0].Witness = [][]byte{sig}

	if err := ExecuteScript(nil, prevScripts[0], tx, 0, amount, prevScripts, prevAmounts, testChainID); err != nil {
		t.Errorf("valid P2TR key-path: unexpected error: %v", err)
	}
}

func TestExecuteScript_P2TR_KeyPath_RejectsTamperedMessage(t *testing.T) {
	priv, pub, _ := crypto.GenerateKeyPair()
	xonly, _ := crypto.XOnlyPubKey(pub)
	amount := int64(500_000)
	tx, prevScripts, prevAmounts := buildP2TRTx(t, xonly, amount)
	sigHash, _ := CalcTaprootKeySpendSigHash(tx, 0, prevScripts, prevAmounts, sigHashDefault, testChainID)
	sig, _ := crypto.SchnorrSign(priv, sigHash[:])
	tx.Inputs[0].Witness = [][]byte{sig}

	// Mutate the transaction's output value: sighash commits to outputs, so
	// the existing signature must no longer verify.
	tx.Outputs[0].Value++
	if err := ExecuteScript(nil, prevScripts[0], tx, 0, amount, prevScripts, prevAmounts, testChainID); err == nil {
		t.Error("P2TR must reject signature after output mutation")
	}
}

func TestExecuteScript_P2TR_KeyPath_RejectsWrongKey(t *testing.T) {
	priv1, pub1, _ := crypto.GenerateKeyPair()
	_, pub2, _ := crypto.GenerateKeyPair()
	x1, _ := crypto.XOnlyPubKey(pub1)
	x2, _ := crypto.XOnlyPubKey(pub2)
	amount := int64(500_000)
	// Output committed to x2, but we sign with priv1 — signature won't verify
	// against x2.
	tx, _, prevAmounts := buildP2TRTx(t, x2, amount)
	prevScripts := [][]byte{primitives.P2TRScript([32]byte(x2))}

	sigHash, _ := CalcTaprootKeySpendSigHash(tx, 0, prevScripts, prevAmounts, sigHashDefault, testChainID)
	sig, _ := crypto.SchnorrSign(priv1, sigHash[:])
	tx.Inputs[0].Witness = [][]byte{sig}
	_ = x1

	if err := ExecuteScript(nil, prevScripts[0], tx, 0, amount, prevScripts, prevAmounts, testChainID); err == nil {
		t.Error("P2TR must reject signature from a different key")
	}
}

func TestExecuteScript_P2TR_KeyPath_RejectsNonEmptyScriptSig(t *testing.T) {
	_, pub, _ := crypto.GenerateKeyPair()
	xonly, _ := crypto.XOnlyPubKey(pub)
	amount := int64(1)
	tx, prevScripts, prevAmounts := buildP2TRTx(t, xonly, amount)
	tx.Inputs[0].ScriptSig = []byte{0x01}
	tx.Inputs[0].Witness = [][]byte{make([]byte, 64)}

	if err := ExecuteScript(tx.Inputs[0].ScriptSig, prevScripts[0], tx, 0, amount, prevScripts, prevAmounts, testChainID); err == nil {
		t.Error("P2TR must reject non-empty scriptSig")
	}
}

func TestExecuteScript_P2TR_RejectsEmptyWitness(t *testing.T) {
	_, pub, _ := crypto.GenerateKeyPair()
	xonly, _ := crypto.XOnlyPubKey(pub)
	amount := int64(1)
	tx, prevScripts, prevAmounts := buildP2TRTx(t, xonly, amount)
	tx.Inputs[0].Witness = nil
	if err := ExecuteScript(nil, prevScripts[0], tx, 0, amount, prevScripts, prevAmounts, testChainID); err == nil {
		t.Error("P2TR must reject empty witness")
	}
}

func TestExecuteScript_P2TR_KeyPath_TweakedOutputKey(t *testing.T) {
	// Full BIP-341 loop: derive internal key → TapTweakPubKey → P2TR output
	// → sign with TapTweakSecKey → spend verifies via ExecuteScript.
	// This is the path a taproot wallet follows end-to-end.
	sec, pub, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	internalXOnly, err := crypto.XOnlyPubKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	// Key-path-only taproot: no script tree, merkleRoot = nil.
	outKey, _, err := crypto.TapTweakPubKey(internalXOnly, nil)
	if err != nil {
		t.Fatal(err)
	}
	tweakedSec, err := crypto.TapTweakSecKey(sec, nil)
	if err != nil {
		t.Fatal(err)
	}

	amount := int64(250_000)
	tx, prevScripts, prevAmounts := buildP2TRTx(t, outKey, amount)
	sigHash, err := CalcTaprootKeySpendSigHash(tx, 0, prevScripts, prevAmounts, sigHashDefault, testChainID)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := crypto.SchnorrSign(tweakedSec, sigHash[:])
	if err != nil {
		t.Fatal(err)
	}
	tx.Inputs[0].Witness = [][]byte{sig}

	if err := ExecuteScript(nil, prevScripts[0], tx, 0, amount, prevScripts, prevAmounts, testChainID); err != nil {
		t.Errorf("tweaked taproot spend must verify: %v", err)
	}

	// Signing with the UNTWEAKED secret must fail — proves the tweak is
	// actually mixed into the output key.
	rawSig, _ := crypto.SchnorrSign(sec, sigHash[:])
	tx.Inputs[0].Witness = [][]byte{rawSig}
	if err := ExecuteScript(nil, prevScripts[0], tx, 0, amount, prevScripts, prevAmounts, testChainID); err == nil {
		t.Error("untweaked secret must not satisfy a tweaked P2TR output")
	}
}

func TestExecuteScript_P2TR_KeyPath_RejectsExplicitSighashDefault(t *testing.T) {
	// BIP-341: a 65-byte signature whose trailing sighash type byte is 0x00
	// is invalid — the 64-byte form is the only way to represent
	// SIGHASH_DEFAULT.
	priv, pub, _ := crypto.GenerateKeyPair()
	xonly, _ := crypto.XOnlyPubKey(pub)
	amount := int64(1)
	tx, prevScripts, prevAmounts := buildP2TRTx(t, xonly, amount)
	sigHash, _ := CalcTaprootKeySpendSigHash(tx, 0, prevScripts, prevAmounts, sigHashDefault, testChainID)
	sig, _ := crypto.SchnorrSign(priv, sigHash[:])
	tx.Inputs[0].Witness = [][]byte{append(sig, 0x00)} // explicit 0x00

	if err := ExecuteScript(nil, prevScripts[0], tx, 0, amount, prevScripts, prevAmounts, testChainID); err == nil {
		t.Error("P2TR must reject 65-byte signature with trailing 0x00 sighash type")
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
