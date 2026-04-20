package chain

import (
	"bytes"
	"testing"

	"github.com/computervirtualservices/malairte/internal/crypto"
	"github.com/computervirtualservices/malairte/internal/primitives"
)

// buildTapscriptSpend builds a P2TR output committed to a single tapscript
// leaf and the transaction that spends it. Returns the script, the leaf
// hash, the control block, the tx, and prevout vectors.
//
// The P2TR output key is computed by tweaking internalKey with the leaf's
// tapbranch (which, for a single-leaf tree, equals the leaf hash itself).
func buildTapscriptSpend(
	t *testing.T,
	internalPub []byte,
	script []byte,
	amount int64,
) (leafHash [32]byte, controlBlock []byte, tx *primitives.Transaction, prevScripts [][]byte, prevAmounts []int64) {
	t.Helper()
	internalXOnly, err := crypto.XOnlyPubKey(internalPub)
	if err != nil {
		t.Fatalf("XOnlyPubKey: %v", err)
	}
	leafHash = crypto.TapLeafHash(crypto.TapLeafVersion, script)

	// Single-leaf tree: merkle root == leaf hash.
	tweakedKey, oddY, err := crypto.TapTweakPubKey(internalXOnly, leafHash[:])
	if err != nil {
		t.Fatalf("TapTweakPubKey: %v", err)
	}

	// Control block: leaf_version (with parity bit) || internal key, no path.
	var parityBit byte
	if oddY {
		parityBit = 1
	}
	controlBlock = append([]byte{crypto.TapLeafVersion | parityBit}, internalXOnly...)

	// Build the spending transaction with a P2TR output committing tweakedKey.
	var outKey [32]byte
	copy(outKey[:], tweakedKey)
	spk := primitives.P2TRScript(outKey)
	tx = &primitives.Transaction{
		Version: 2,
		Inputs: []primitives.TxInput{{
			PreviousOutput: primitives.OutPoint{TxID: [32]byte{0xCC}, Index: 0},
			Sequence:       0xFFFFFFFF,
		}},
		Outputs: []primitives.TxOutput{{
			Value:        amount - 1_000,
			ScriptPubKey: primitives.P2PKHScript([20]byte{0xFE}),
		}},
		LockTime: 0,
	}
	prevScripts = [][]byte{spk}
	prevAmounts = []int64{amount}
	return
}

// TestExecuteScript_P2TR_ScriptPath_SingleSig covers the canonical single-key
// tapscript: <pubkey> OP_CHECKSIG. The spender signs the tapscript sighash
// (BIP-342 ext-flag=1) and provides [signature, script, control_block] as
// the witness.
func TestExecuteScript_P2TR_ScriptPath_SingleSig(t *testing.T) {
	sigPriv, sigPub, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, internalPub, _ := crypto.GenerateKeyPair()

	sigXOnly, err := crypto.XOnlyPubKey(sigPub)
	if err != nil {
		t.Fatal(err)
	}
	// Tapscript: <push 32> <xonly pubkey> <OP_CHECKSIG>
	script := append([]byte{0x20}, sigXOnly...)
	script = append(script, 0xac)

	amount := int64(500_000)
	leafHash, controlBlock, tx, prevScripts, prevAmounts := buildTapscriptSpend(t, internalPub, script, amount)

	sigHash, err := CalcTapScriptSigHash(tx, 0, prevScripts, prevAmounts, sigHashDefault, leafHash, testChainID)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := crypto.SchnorrSign(sigPriv, sigHash[:])
	if err != nil {
		t.Fatal(err)
	}
	tx.Inputs[0].Witness = [][]byte{sig, script, controlBlock}

	if err := ExecuteScript(nil, prevScripts[0], tx, 0, amount, prevScripts, prevAmounts, testChainID); err != nil {
		t.Errorf("valid script-path spend: %v", err)
	}
}

// TestExecuteScript_P2TR_ScriptPath_CheckSigAddMultisig covers the BIP-342
// 2-of-3 multisig pattern that replaces OP_CHECKMULTISIG:
//   <sig_a_or_empty> <sig_b_or_empty> <sig_c_or_empty>
//   <pk_a> OP_CHECKSIG <pk_b> OP_CHECKSIGADD <pk_c> OP_CHECKSIGADD OP_2 OP_EQUAL
// Non-signers push an empty 0-byte signature; CHECKSIG treats that as "not
// valid" without failing. The final OP_EQUAL checks the count equals the
// threshold.
func TestExecuteScript_P2TR_ScriptPath_CheckSigAddMultisig(t *testing.T) {
	_, internalPub, _ := crypto.GenerateKeyPair()
	privA, pubA, _ := crypto.GenerateKeyPair()
	privB, pubB, _ := crypto.GenerateKeyPair()
	_, pubC, _ := crypto.GenerateKeyPair()

	xonlyA, _ := crypto.XOnlyPubKey(pubA)
	xonlyB, _ := crypto.XOnlyPubKey(pubB)
	xonlyC, _ := crypto.XOnlyPubKey(pubC)

	// Script assembly:
	//   <push32> xonlyA OP_CHECKSIG
	//   <push32> xonlyB OP_CHECKSIGADD
	//   <push32> xonlyC OP_CHECKSIGADD
	//   OP_2 OP_EQUAL
	var script []byte
	script = append(script, 0x20)
	script = append(script, xonlyA...)
	script = append(script, 0xac) // CHECKSIG
	script = append(script, 0x20)
	script = append(script, xonlyB...)
	script = append(script, 0xba) // CHECKSIGADD
	script = append(script, 0x20)
	script = append(script, xonlyC...)
	script = append(script, 0xba) // CHECKSIGADD
	script = append(script, 0x52) // OP_2
	script = append(script, 0x87) // OP_EQUAL

	amount := int64(700_000)
	leafHash, controlBlock, tx, prevScripts, prevAmounts := buildTapscriptSpend(t, internalPub, script, amount)

	sigHash, err := CalcTapScriptSigHash(tx, 0, prevScripts, prevAmounts, sigHashDefault, leafHash, testChainID)
	if err != nil {
		t.Fatal(err)
	}
	sigA, _ := crypto.SchnorrSign(privA, sigHash[:])
	sigB, _ := crypto.SchnorrSign(privB, sigHash[:])

	// Stack order (bottom to top before script runs): sigA, sigB, <empty for C>
	// Script reads top-first, so after stack builds, OP_CHECKSIG pops xonlyA
	// then pops what it thinks is sigA. Tapscript pushes in reverse: witness
	// items are pushed left-to-right, so the first item lands at the bottom.
	// Our script checks A first, so sigA must be bottom of the input stack.
	// But the script itself pushes xonlyA just before OP_CHECKSIG, so
	// OP_CHECKSIG sees [..., sigA, xonlyA]. Hence stack bottom-to-top is:
	// empty_for_C, sigB, sigA — pushed left-to-right in that order.
	tx.Inputs[0].Witness = [][]byte{{}, sigB, sigA, script, controlBlock}

	if err := ExecuteScript(nil, prevScripts[0], tx, 0, amount, prevScripts, prevAmounts, testChainID); err != nil {
		t.Errorf("valid 2-of-3 CHECKSIGADD multisig: %v", err)
	}

	// Negative: only 1 signature should fail OP_EQUAL (count=1 vs OP_2).
	tx.Inputs[0].Witness = [][]byte{{}, {}, sigA, script, controlBlock}
	if err := ExecuteScript(nil, prevScripts[0], tx, 0, amount, prevScripts, prevAmounts, testChainID); err == nil {
		t.Error("1-of-3 must fail 2-of-3 threshold")
	}
}

func TestExecuteScript_P2TR_ScriptPath_RejectsBadControlBlock(t *testing.T) {
	sigPriv, sigPub, _ := crypto.GenerateKeyPair()
	_, internalPub, _ := crypto.GenerateKeyPair()
	sigXOnly, _ := crypto.XOnlyPubKey(sigPub)
	script := append([]byte{0x20}, sigXOnly...)
	script = append(script, 0xac)
	amount := int64(100)
	leafHash, controlBlock, tx, prevScripts, prevAmounts := buildTapscriptSpend(t, internalPub, script, amount)

	sigHash, _ := CalcTapScriptSigHash(tx, 0, prevScripts, prevAmounts, sigHashDefault, leafHash, testChainID)
	sig, _ := crypto.SchnorrSign(sigPriv, sigHash[:])

	// Flip a bit in the internal key portion of the control block → merkle
	// commitment will no longer verify.
	bad := append([]byte(nil), controlBlock...)
	bad[5] ^= 0x01
	tx.Inputs[0].Witness = [][]byte{sig, script, bad}
	if err := ExecuteScript(nil, prevScripts[0], tx, 0, amount, prevScripts, prevAmounts, testChainID); err == nil {
		t.Error("tampered internal key in control block must fail commitment check")
	}

	// Truncated control block (< 33 bytes) — parse must reject before any
	// crypto runs.
	tx.Inputs[0].Witness = [][]byte{sig, script, controlBlock[:20]}
	if err := ExecuteScript(nil, prevScripts[0], tx, 0, amount, prevScripts, prevAmounts, testChainID); err == nil {
		t.Error("truncated control block must be rejected")
	}
}

func TestTapscript_OpCLTV(t *testing.T) {
	// Leaf: <locktime=500> OP_CHECKLOCKTIMEVERIFY OP_DROP <pk> OP_CHECKSIG.
	// The OP_DROP is required because CLTV is a "verify" opcode that leaves
	// the operand on the stack.
	sigPriv, sigPub, _ := crypto.GenerateKeyPair()
	_, internalPub, _ := crypto.GenerateKeyPair()
	sigXOnly, _ := crypto.XOnlyPubKey(sigPub)

	// script: push 500 (2 bytes, minimal encoding: 0xf4 0x01) OP_CLTV OP_DROP <push32> xonly OP_CHECKSIG
	script := []byte{
		0x02, 0xf4, 0x01, // push 500 little-endian (= int64 500)
		0xb1,             // OP_CHECKLOCKTIMEVERIFY
		0x75,             // OP_DROP
		0x20,             // push 32
	}
	script = append(script, sigXOnly...)
	script = append(script, 0xac)

	amount := int64(100)
	leafHash, controlBlock, tx, prevScripts, prevAmounts := buildTapscriptSpend(t, internalPub, script, amount)
	// Set tx locktime = 500 exactly, sequence non-final so locktime is active.
	tx.LockTime = 500
	tx.Inputs[0].Sequence = 0xFFFFFFFE

	sigHash, _ := CalcTapScriptSigHash(tx, 0, prevScripts, prevAmounts, sigHashDefault, leafHash, testChainID)
	sig, _ := crypto.SchnorrSign(sigPriv, sigHash[:])
	tx.Inputs[0].Witness = [][]byte{sig, script, controlBlock}
	if err := ExecuteScript(nil, prevScripts[0], tx, 0, amount, prevScripts, prevAmounts, testChainID); err != nil {
		t.Errorf("CLTV-satisfying spend: %v", err)
	}

	// Now lower tx.LockTime below the required value — must fail.
	tx.LockTime = 499
	// Re-sign because locktime is committed in the sighash.
	sigHash, _ = CalcTapScriptSigHash(tx, 0, prevScripts, prevAmounts, sigHashDefault, leafHash, testChainID)
	sig, _ = crypto.SchnorrSign(sigPriv, sigHash[:])
	tx.Inputs[0].Witness = [][]byte{sig, script, controlBlock}
	if err := ExecuteScript(nil, prevScripts[0], tx, 0, amount, prevScripts, prevAmounts, testChainID); err == nil {
		t.Error("CLTV with txLockTime < required must fail")
	}
}

func TestTapscript_OpCSV_BlockBased(t *testing.T) {
	// Leaf: <relativeBlocks=5> OP_CSV OP_DROP <pk> OP_CHECKSIG
	// Requires tx.Version ≥ 2 and input.Sequence block-delay ≥ 5.
	sigPriv, sigPub, _ := crypto.GenerateKeyPair()
	_, internalPub, _ := crypto.GenerateKeyPair()
	sigXOnly, _ := crypto.XOnlyPubKey(sigPub)

	script := []byte{
		0x01, 0x05, // push 5
		0xb2,       // OP_CHECKSEQUENCEVERIFY
		0x75,       // OP_DROP
		0x20,       // push 32
	}
	script = append(script, sigXOnly...)
	script = append(script, 0xac)

	amount := int64(100)
	leafHash, controlBlock, tx, prevScripts, prevAmounts := buildTapscriptSpend(t, internalPub, script, amount)
	tx.Version = 2
	// Satisfying: input sequence encodes ≥5 block delay, disable flag clear, type=block.
	tx.Inputs[0].Sequence = 5

	sigHash, _ := CalcTapScriptSigHash(tx, 0, prevScripts, prevAmounts, sigHashDefault, leafHash, testChainID)
	sig, _ := crypto.SchnorrSign(sigPriv, sigHash[:])
	tx.Inputs[0].Witness = [][]byte{sig, script, controlBlock}
	if err := ExecuteScript(nil, prevScripts[0], tx, 0, amount, prevScripts, prevAmounts, testChainID); err != nil {
		t.Errorf("CSV-satisfying spend: %v", err)
	}

	// Insufficient sequence: 4 < 5 → must fail.
	tx.Inputs[0].Sequence = 4
	sigHash, _ = CalcTapScriptSigHash(tx, 0, prevScripts, prevAmounts, sigHashDefault, leafHash, testChainID)
	sig, _ = crypto.SchnorrSign(sigPriv, sigHash[:])
	tx.Inputs[0].Witness = [][]byte{sig, script, controlBlock}
	if err := ExecuteScript(nil, prevScripts[0], tx, 0, amount, prevScripts, prevAmounts, testChainID); err == nil {
		t.Error("CSV with sequence < required must fail")
	}

	// Version=1 → CSV must fail even with satisfying sequence.
	tx.Version = 1
	tx.Inputs[0].Sequence = 5
	sigHash, _ = CalcTapScriptSigHash(tx, 0, prevScripts, prevAmounts, sigHashDefault, leafHash, testChainID)
	sig, _ = crypto.SchnorrSign(sigPriv, sigHash[:])
	tx.Inputs[0].Witness = [][]byte{sig, script, controlBlock}
	if err := ExecuteScript(nil, prevScripts[0], tx, 0, amount, prevScripts, prevAmounts, testChainID); err == nil {
		t.Error("CSV with tx.Version<2 must fail")
	}
}

func TestTapscript_OpCTV(t *testing.T) {
	// A UTXO whose tapscript is:
	//   <templateHash:32> OP_CHECKTEMPLATEVERIFY
	// can only be spent by a tx that matches templateHash. The script itself
	// never verifies a signature — the template commitment IS the
	// authorization, which is what makes this a covenant.
	//
	// For the positive case we: build a candidate spending tx, compute its
	// standard template hash, compile that hash into the leaf script, and
	// verify the spend. Negative case: change an output after compilation
	// and assert rejection.
	_, internalPub, _ := crypto.GenerateKeyPair()

	amount := int64(100_000)
	// First build a provisional tx to capture its shape.
	provisional := &primitives.Transaction{
		Version: 1,
		Inputs: []primitives.TxInput{{
			PreviousOutput: primitives.OutPoint{TxID: [32]byte{0xAB}, Index: 0},
			Sequence:       0xFFFFFFFF,
		}},
		Outputs: []primitives.TxOutput{{
			Value:        amount - 1_000,
			ScriptPubKey: primitives.P2PKHScript([20]byte{0xCC}),
		}},
	}
	templHash := standardTemplateHash(provisional, 0)

	// Compile the leaf: push 32-byte templHash, OP_CTV.
	script := append([]byte{0x20}, templHash[:]...)
	script = append(script, 0xb3) // OP_CHECKTEMPLATEVERIFY

	leafHash, controlBlock, tx, prevScripts, prevAmounts := buildTapscriptSpend(t, internalPub, script, amount)
	// buildTapscriptSpend produced a *different* provisional tx; rewrite it
	// to match what we computed the template hash over. This mirrors how
	// a real covenant-issuing tool would work: the template is fixed, and
	// the spend MUST take that exact shape.
	tx.Version = provisional.Version
	tx.Inputs = provisional.Inputs
	tx.Outputs = provisional.Outputs
	tx.LockTime = provisional.LockTime
	_ = leafHash
	tx.Inputs[0].Witness = [][]byte{script, controlBlock}

	if err := ExecuteScript(nil, prevScripts[0], tx, 0, amount, prevScripts, prevAmounts, testChainID); err != nil {
		t.Errorf("CTV-matching spend must verify: %v", err)
	}

	// Mutate an output — template hash no longer matches.
	tx.Outputs[0].Value++
	tx.Inputs[0].Witness = [][]byte{script, controlBlock}
	if err := ExecuteScript(nil, prevScripts[0], tx, 0, amount, prevScripts, prevAmounts, testChainID); err == nil {
		t.Error("CTV must reject mutated outputs")
	}
}

func TestExecuteScript_P2TR_ScriptPath_RejectsWrongScript(t *testing.T) {
	sigPriv, sigPub, _ := crypto.GenerateKeyPair()
	_, internalPub, _ := crypto.GenerateKeyPair()
	sigXOnly, _ := crypto.XOnlyPubKey(sigPub)
	realScript := append([]byte{0x20}, sigXOnly...)
	realScript = append(realScript, 0xac)

	amount := int64(100)
	leafHash, controlBlock, tx, prevScripts, prevAmounts := buildTapscriptSpend(t, internalPub, realScript, amount)
	sigHash, _ := CalcTapScriptSigHash(tx, 0, prevScripts, prevAmounts, sigHashDefault, leafHash, testChainID)
	sig, _ := crypto.SchnorrSign(sigPriv, sigHash[:])

	// Replace the script with a different one — control block no longer
	// commits to it, so the merkle check must fail.
	otherScript := append(append([]byte{0x20}, sigXOnly...), 0xac, 0x75) // trailing OP_DROP
	_ = bytes.Equal
	tx.Inputs[0].Witness = [][]byte{sig, otherScript, controlBlock}
	if err := ExecuteScript(nil, prevScripts[0], tx, 0, amount, prevScripts, prevAmounts, testChainID); err == nil {
		t.Error("script swap must fail taproot commitment verification")
	}
}
