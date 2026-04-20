package chain

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/computervirtualservices/malairte/internal/crypto"
	"github.com/computervirtualservices/malairte/internal/primitives"
)

// sigHashAll is the only supported SIGHASH type: sign all inputs and outputs.
const sigHashAll byte = 0x01

// ExecuteScript verifies scriptSig (input unlocking script) against scriptPubKey
// (UTXO locking script) for the input at inputIdx inside tx.
//
// amount is the atom value of the UTXO being spent — required by BIP-143 for
// SegWit v0 inputs; ignored for legacy P2PKH.
//
// prevoutScripts and prevoutAmounts are the full vectors of every input's
// spent scriptPubKey and value, in input order. Required by BIP-341 taproot:
// a taproot signature commits to every spent UTXO, not just the one at
// inputIdx. Callers validating a non-taproot transaction may pass nil/empty
// — the P2PKH and P2WPKH paths do not consult them.
//
// chainID is mixed into every sighash so a signature valid on one network
// cannot be replayed on another (mainnet ↔ testnet).
//
// Supports P2PKH (legacy), P2WPKH (SegWit v0) and P2TR key-path (SegWit v1).
// Any other scriptPubKey is passed permissively until a full script
// interpreter is in place.
func ExecuteScript(
	scriptSig, scriptPubKey []byte,
	tx *primitives.Transaction,
	inputIdx int,
	amount int64,
	prevoutScripts [][]byte,
	prevoutAmounts []int64,
	chainID uint32,
) error {
	if primitives.IsP2PKHScript(scriptPubKey) {
		return executeP2PKH(scriptSig, scriptPubKey, tx, inputIdx, chainID)
	}
	if primitives.IsP2WPKHScript(scriptPubKey) {
		return executeP2WPKH(scriptSig, scriptPubKey, tx, inputIdx, amount, chainID)
	}
	if primitives.IsP2TRScript(scriptPubKey) {
		return executeP2TR(scriptSig, scriptPubKey, tx, inputIdx, prevoutScripts, prevoutAmounts, chainID)
	}
	// Unknown script: permissive until full interpreter is in place
	return nil
}

// executeP2TR routes a taproot spend to the appropriate spend path per
// BIP-341: a single-item witness is a key-path spend; any other shape is a
// script-path spend (the last witness item is the control block, the
// second-to-last is the tapscript, and everything before is the script's
// input stack). Zero-item witnesses are rejected by executeP2TRKeyPath.
func executeP2TR(
	scriptSig, scriptPubKey []byte,
	tx *primitives.Transaction,
	inputIdx int,
	prevoutScripts [][]byte,
	prevoutAmounts []int64,
	chainID uint32,
) error {
	if len(scriptSig) != 0 {
		return errors.New("P2TR input must have empty scriptSig")
	}
	witness := tx.Inputs[inputIdx].Witness
	if len(witness) == 1 {
		return executeP2TRKeyPath(scriptSig, scriptPubKey, tx, inputIdx, prevoutScripts, prevoutAmounts, chainID)
	}
	if len(witness) == 0 {
		return errors.New("P2TR input has empty witness")
	}
	return executeP2TRScriptPath(scriptPubKey, tx, inputIdx, prevoutScripts, prevoutAmounts, chainID)
}

// executeP2TRScriptPath verifies a BIP-341/342 taproot script-path spend.
// Witness layout: [stack_item_0, ..., stack_item_n, script, control_block].
//  1. Parse the control block, reject malformed shapes.
//  2. Compute the tapleaf hash from script + leaf version.
//  3. Walk the merkle path through TapBranch hashes to produce a merkle root.
//  4. Verify that TapTweakPubKey(internalKey, root) == output key, with
//     matching parity.
//  5. Run the tapscript interpreter against the script-input stack.
func executeP2TRScriptPath(
	scriptPubKey []byte,
	tx *primitives.Transaction,
	inputIdx int,
	prevoutScripts [][]byte,
	prevoutAmounts []int64,
	chainID uint32,
) error {
	witness := tx.Inputs[inputIdx].Witness
	// Annex (last item starts with 0x50) is not supported.
	if last := witness[len(witness)-1]; len(last) > 0 && last[0] == 0x50 {
		return errors.New("P2TR: annex is not supported")
	}

	// Split witness: last item is control block, previous is script, rest is stack.
	ctrlRaw := witness[len(witness)-1]
	script := witness[len(witness)-2]
	stackInputs := witness[:len(witness)-2]

	cb, err := parseControlBlock(ctrlRaw)
	if err != nil {
		return err
	}
	if cb.LeafVersion != crypto.TapLeafVersion {
		return fmt.Errorf("P2TR: unsupported leaf version 0x%02x", cb.LeafVersion)
	}

	leafHash := crypto.TapLeafHash(cb.LeafVersion, script)

	outputKey, ok := primitives.ExtractP2TRKey(scriptPubKey)
	if !ok {
		return errors.New("P2TR: malformed scriptPubKey")
	}
	if err := verifyTaprootCommitment(cb, leafHash, outputKey[:]); err != nil {
		return err
	}

	return executeTapScript(
		script,
		stackInputs,
		tx, inputIdx,
		prevoutScripts, prevoutAmounts,
		leafHash,
		chainID,
	)
}

// executeP2TRKeyPath verifies a BIP-341 taproot key-path spend:
//  1. ScriptSig MUST be empty (all taproot witness programs).
//  2. The witness stack MUST contain exactly one element (the signature).
//     Script-path spends have ≥2 elements and are handled by a separate path
//     once tapscript lands.
//  3. The signature is 64 bytes (implicit SIGHASH_DEFAULT = 0x00) or 65 bytes
//     (explicit sighash type in the trailing byte; must not be 0x00).
//  4. The 32-byte x-only output key from the scriptPubKey is used directly
//     as the Schnorr pubkey. (Tweaking is a wallet/spender concern — the
//     consensus check is "this signature must verify against the key
//     committed in the output".)
func executeP2TRKeyPath(
	scriptSig, scriptPubKey []byte,
	tx *primitives.Transaction,
	inputIdx int,
	prevoutScripts [][]byte,
	prevoutAmounts []int64,
	chainID uint32,
) error {
	if len(scriptSig) != 0 {
		return errors.New("P2TR input must have empty scriptSig")
	}
	xonly, ok := primitives.ExtractP2TRKey(scriptPubKey)
	if !ok {
		return errors.New("malformed P2TR scriptPubKey")
	}
	witness := tx.Inputs[inputIdx].Witness
	if len(witness) != 1 {
		return fmt.Errorf("P2TR key-path witness must have 1 item, got %d", len(witness))
	}
	sig := witness[0]

	var hashType byte
	var sigBytes []byte
	switch len(sig) {
	case 64:
		hashType = sigHashDefault
		sigBytes = sig
	case 65:
		// Last byte is the explicit sighash type; 0x00 is reserved for the
		// 64-byte form (BIP-341 mandates this to avoid malleability).
		if sig[64] == sigHashDefault {
			return errors.New("P2TR: explicit sighash type must not be 0x00 (use 64-byte form)")
		}
		hashType = sig[64]
		sigBytes = sig[:64]
	default:
		return fmt.Errorf("P2TR signature must be 64 or 65 bytes, got %d", len(sig))
	}

	sigHash, err := CalcTaprootKeySpendSigHash(tx, inputIdx, prevoutScripts, prevoutAmounts, hashType, chainID)
	if err != nil {
		return fmt.Errorf("P2TR sighash: %w", err)
	}
	if !crypto.SchnorrVerify(xonly[:], sigHash[:], sigBytes) {
		return errors.New("invalid P2TR signature")
	}
	return nil
}

// executeP2WPKH verifies a native SegWit v0 P2WPKH spend:
//  1. ScriptSig MUST be empty (witness programs must not carry scriptSig data).
//  2. The input's witness stack MUST be exactly [signature, pubkey].
//  3. Hash160(pubkey) MUST equal the 20-byte hash in the output script.
//  4. The DER signature (minus its trailing sighash type byte) MUST verify
//     against the BIP-143 sighash for this input, with scriptCode set to the
//     equivalent P2PKH script of the pkh.
func executeP2WPKH(scriptSig, scriptPubKey []byte, tx *primitives.Transaction, inputIdx int, amount int64, chainID uint32) error {
	if len(scriptSig) != 0 {
		return errors.New("P2WPKH input must have empty scriptSig")
	}
	expectedHash, ok := primitives.ExtractP2WPKHHash(scriptPubKey)
	if !ok {
		return errors.New("malformed P2WPKH scriptPubKey")
	}
	witness := tx.Inputs[inputIdx].Witness
	if len(witness) != 2 {
		return fmt.Errorf("P2WPKH witness must have 2 items, got %d", len(witness))
	}
	sig := witness[0]
	pubKey := witness[1]
	if len(pubKey) != 33 {
		return fmt.Errorf("P2WPKH pubkey must be 33-byte compressed, got %d bytes", len(pubKey))
	}
	if crypto.Hash160(pubKey) != expectedHash {
		return errors.New("P2WPKH pubkey hash mismatch")
	}
	if len(sig) < 2 {
		return errors.New("P2WPKH signature too short")
	}
	if sig[len(sig)-1] != sigHashAll {
		return fmt.Errorf("P2WPKH unsupported sighash type 0x%02x", sig[len(sig)-1])
	}
	derSig := sig[:len(sig)-1]

	// BIP-143: scriptCode for P2WPKH is the P2PKH script of the pkh.
	scriptCode := primitives.P2PKHScript(expectedHash)
	sigHash := CalcSigHashWitnessV0(tx, inputIdx, scriptCode, amount, chainID)
	if !crypto.Verify(pubKey, sigHash[:], derSig) {
		return errors.New("invalid P2WPKH signature")
	}
	return nil
}

// executeP2PKH implements the six-step P2PKH verification shortcut:
//  1. Parse <sig> and <pubkey> from scriptSig.
//  2. Verify Hash160(pubkey) == expectedHash from scriptPubKey (OP_HASH160 + OP_EQUALVERIFY).
//  3. Strip the sighash-type byte and recompute the transaction signature hash.
//  4. Verify the DER-encoded ECDSA signature (OP_CHECKSIG).
func executeP2PKH(scriptSig, scriptPubKey []byte, tx *primitives.Transaction, inputIdx int, chainID uint32) error {
	sig, pubKey, err := parseP2PKHScriptSig(scriptSig)
	if err != nil {
		return fmt.Errorf("invalid P2PKH scriptSig: %w", err)
	}

	expectedHash, ok := primitives.ExtractP2PKHHash(scriptPubKey)
	if !ok {
		return errors.New("malformed P2PKH scriptPubKey")
	}

	// OP_HASH160 / OP_EQUALVERIFY
	if crypto.Hash160(pubKey) != expectedHash {
		return errors.New("pubkey hash mismatch")
	}

	// Strip the trailing sighash-type byte from the encoded signature
	if len(sig) < 2 {
		return errors.New("signature too short")
	}
	if sig[len(sig)-1] != sigHashAll {
		return fmt.Errorf("unsupported sighash type 0x%02x", sig[len(sig)-1])
	}
	derSig := sig[:len(sig)-1]

	// OP_CHECKSIG
	sigHash := calcSigHash(tx, inputIdx, scriptPubKey, chainID)
	if !crypto.Verify(pubKey, sigHash[:], derSig) {
		return errors.New("invalid signature")
	}

	return nil
}

// parseP2PKHScriptSig decodes a standard P2PKH scriptSig into its two pushes:
// <DER-sig + sighash-type byte> and <compressed 33-byte pubkey>.
func parseP2PKHScriptSig(script []byte) (sig, pubKey []byte, err error) {
	sig, n, err := readDataPush(script, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("sig push: %w", err)
	}
	pubKey, _, err = readDataPush(script, n)
	if err != nil {
		return nil, nil, fmt.Errorf("pubkey push: %w", err)
	}
	if len(pubKey) != 33 {
		return nil, nil, fmt.Errorf("expected 33-byte compressed pubkey, got %d bytes", len(pubKey))
	}
	return sig, pubKey, nil
}

// readDataPush reads one data-push opcode and its payload from script at pos.
// Supports direct pushes (0x01–0x4b), OP_PUSHDATA1 (0x4c), and OP_PUSHDATA2 (0x4d).
// Returns the pushed bytes and the total number of bytes consumed.
func readDataPush(script []byte, pos int) (data []byte, consumed int, err error) {
	if pos >= len(script) {
		return nil, 0, errors.New("script: unexpected end of data")
	}

	op := script[pos]
	pos++
	consumed = 1

	var length int
	switch {
	case op >= 0x01 && op <= 0x4b:
		length = int(op)
	case op == 0x4c: // OP_PUSHDATA1 — next byte is the length
		if pos >= len(script) {
			return nil, 0, errors.New("OP_PUSHDATA1: missing length byte")
		}
		length = int(script[pos])
		pos++
		consumed++
	case op == 0x4d: // OP_PUSHDATA2 — next 2 bytes LE are the length
		if pos+2 > len(script) {
			return nil, 0, errors.New("OP_PUSHDATA2: missing length bytes")
		}
		length = int(binary.LittleEndian.Uint16(script[pos : pos+2]))
		pos += 2
		consumed += 2
	default:
		return nil, 0, fmt.Errorf("script: unsupported opcode 0x%02x at offset %d", op, pos-1)
	}

	if pos+length > len(script) {
		return nil, 0, fmt.Errorf("script: push overflows script boundary (need %d bytes)", length)
	}
	data = script[pos : pos+length]
	consumed += length
	return data, consumed, nil
}

// CalcSigHash is the exported wrapper around calcSigHash for use by transaction
// builders (e.g. the payout sweeper) that need to produce signatures matching
// the on-chain validator's expectations. chainID is the ChainParams.Net value;
// pass the same chain id the validator will use or signatures will not verify.
func CalcSigHash(tx *primitives.Transaction, inputIdx int, subscript []byte, chainID uint32) [32]byte {
	return calcSigHash(tx, inputIdx, subscript, chainID)
}

// BuildP2PKHScriptSig produces a standard P2PKH unlock script:
//   <der_sig + sigHashAll byte> <compressed_pubKey>
//
// sig should be the raw DER signature returned by crypto.Sign — the SIGHASH
// type byte is appended automatically. pubKey must be the 33-byte compressed
// public key matching the address being spent.
func BuildP2PKHScriptSig(sig, pubKey []byte) []byte {
	sigWithType := make([]byte, len(sig)+1)
	copy(sigWithType, sig)
	sigWithType[len(sig)] = sigHashAll

	out := make([]byte, 0, 2+len(sigWithType)+len(pubKey))
	out = append(out, byte(len(sigWithType)))
	out = append(out, sigWithType...)
	out = append(out, byte(len(pubKey)))
	out = append(out, pubKey...)
	return out
}

// calcSigHash computes the SIGHASH_ALL preimage hash for input inputIdx in tx.
//
// Malairt SIGHASH_ALL serialization (Bitcoin-compatible with chain-ID prefix):
//   - chainID (4 bytes LE) — ChainParams.Net, binds signature to this network
//   - version (4 bytes LE)
//   - varint(inputCount) + inputs: TxID(32) + index(4) + scriptSig(subscript for
//     inputIdx, empty for all others) + sequence(4)
//   - varint(outputCount) + outputs: value(8) + scriptPubKey
//   - locktime (4 bytes LE)
//   - hashType (4 bytes LE, 0x00000001 for SIGHASH_ALL)
//
// The chain-ID prefix is a replay-protection measure: a signature produced for
// mainnet (chainID=0x4d4c5254) will not verify on testnet (chainID=0x4d4c7274)
// or vice versa. Wallets must prepend the correct chain id before hashing.
//
// Returns Hash256 (double-SHA256) of the resulting byte slice.
func calcSigHash(tx *primitives.Transaction, inputIdx int, subscript []byte, chainID uint32) [32]byte {
	buf := make([]byte, 0, 256)
	var tmp [8]byte

	// chainID (replay protection)
	binary.LittleEndian.PutUint32(tmp[:4], chainID)
	buf = append(buf, tmp[:4]...)

	// version
	binary.LittleEndian.PutUint32(tmp[:4], tx.Version)
	buf = append(buf, tmp[:4]...)

	// inputs
	buf = append(buf, primitives.EncodeVarIntPub(uint64(len(tx.Inputs)))...)
	for i, in := range tx.Inputs {
		buf = append(buf, in.PreviousOutput.TxID[:]...)
		binary.LittleEndian.PutUint32(tmp[:4], in.PreviousOutput.Index)
		buf = append(buf, tmp[:4]...)
		if i == inputIdx {
			buf = append(buf, primitives.EncodeVarIntPub(uint64(len(subscript)))...)
			buf = append(buf, subscript...)
		} else {
			buf = append(buf, 0x00) // empty scriptSig varint
		}
		binary.LittleEndian.PutUint32(tmp[:4], in.Sequence)
		buf = append(buf, tmp[:4]...)
	}

	// outputs
	buf = append(buf, primitives.EncodeVarIntPub(uint64(len(tx.Outputs)))...)
	for _, out := range tx.Outputs {
		binary.LittleEndian.PutUint64(tmp[:8], uint64(out.Value))
		buf = append(buf, tmp[:8]...)
		buf = append(buf, primitives.EncodeVarIntPub(uint64(len(out.ScriptPubKey)))...)
		buf = append(buf, out.ScriptPubKey...)
	}

	// locktime
	binary.LittleEndian.PutUint32(tmp[:4], tx.LockTime)
	buf = append(buf, tmp[:4]...)

	// SIGHASH type as 4-byte LE
	binary.LittleEndian.PutUint32(tmp[:4], uint32(sigHashAll))
	buf = append(buf, tmp[:4]...)

	return crypto.Hash256(buf)
}

// Taproot sighash types we accept. SIGHASH_DEFAULT is the BIP-341 implicit
// all-inputs/all-outputs case used when the witness signature is exactly 64
// bytes; the explicit encoding is SIGHASH_ALL (0x01), which produces the same
// preimage.
const (
	sigHashDefault byte = 0x00
)

// CalcTaprootKeySpendSigHash computes the BIP-341 signature hash for a
// taproot key-path spend at inputIdx. prevoutScripts and prevoutAmounts must
// each have one entry per input of tx — BIP-341 commits to every spent
// UTXO's script and value, not just the one being signed, which prevents
// amount-substitution and script-substitution attacks across inputs.
//
// hashType must be 0x00 (SIGHASH_DEFAULT) or 0x01 (SIGHASH_ALL). Other types
// (NONE, SINGLE, ANYONECANPAY) are rejected — support lands with tapscript.
//
// The chainID is prepended to the preimage (inside the tagged hash input),
// matching the replay-protection convention used by the legacy and BIP-143
// sighashes. A signature produced for chain A therefore will not verify on
// chain B, even if the rest of the transaction bytes are identical.
func CalcTaprootKeySpendSigHash(
	tx *primitives.Transaction,
	inputIdx int,
	prevoutScripts [][]byte,
	prevoutAmounts []int64,
	hashType byte,
	chainID uint32,
) ([32]byte, error) {
	if inputIdx < 0 || inputIdx >= len(tx.Inputs) {
		return [32]byte{}, fmt.Errorf("taproot sighash: input index %d out of range", inputIdx)
	}
	if len(prevoutScripts) != len(tx.Inputs) || len(prevoutAmounts) != len(tx.Inputs) {
		return [32]byte{}, errors.New("taproot sighash: prevout vectors must match input count")
	}
	if hashType != sigHashDefault && hashType != sigHashAll {
		return [32]byte{}, fmt.Errorf("taproot sighash: unsupported hash type 0x%02x", hashType)
	}

	var tmp [8]byte

	// Precompute the four cross-input commitments required by BIP-341.
	var (
		shaPrevouts     [32]byte
		shaAmounts      [32]byte
		shaScriptPubKey [32]byte
		shaSequences    [32]byte
		shaOutputs      [32]byte
	)
	{
		var buf []byte
		for _, in := range tx.Inputs {
			buf = append(buf, in.PreviousOutput.TxID[:]...)
			binary.LittleEndian.PutUint32(tmp[:4], in.PreviousOutput.Index)
			buf = append(buf, tmp[:4]...)
		}
		h := sha256.Sum256(buf)
		shaPrevouts = h
	}
	{
		var buf []byte
		for _, amt := range prevoutAmounts {
			binary.LittleEndian.PutUint64(tmp[:8], uint64(amt))
			buf = append(buf, tmp[:8]...)
		}
		shaAmounts = sha256.Sum256(buf)
	}
	{
		var buf []byte
		for _, s := range prevoutScripts {
			buf = append(buf, primitives.EncodeVarIntPub(uint64(len(s)))...)
			buf = append(buf, s...)
		}
		shaScriptPubKey = sha256.Sum256(buf)
	}
	{
		var buf []byte
		for _, in := range tx.Inputs {
			binary.LittleEndian.PutUint32(tmp[:4], in.Sequence)
			buf = append(buf, tmp[:4]...)
		}
		shaSequences = sha256.Sum256(buf)
	}
	{
		var buf []byte
		for _, out := range tx.Outputs {
			binary.LittleEndian.PutUint64(tmp[:8], uint64(out.Value))
			buf = append(buf, tmp[:8]...)
			buf = append(buf, primitives.EncodeVarIntPub(uint64(len(out.ScriptPubKey)))...)
			buf = append(buf, out.ScriptPubKey...)
		}
		shaOutputs = sha256.Sum256(buf)
	}

	// Assemble the preimage per BIP-341 §3.
	buf := make([]byte, 0, 256)

	// chainID prefix (Malairt replay protection).
	binary.LittleEndian.PutUint32(tmp[:4], chainID)
	buf = append(buf, tmp[:4]...)

	// epoch (1 byte, always 0x00 per BIP-341)
	buf = append(buf, 0x00)

	// hash_type (1 byte). For SIGHASH_DEFAULT we serialize 0x00, even though
	// the effective behavior is identical to SIGHASH_ALL.
	buf = append(buf, hashType)

	// nVersion (4 LE), nLockTime (4 LE)
	binary.LittleEndian.PutUint32(tmp[:4], tx.Version)
	buf = append(buf, tmp[:4]...)
	binary.LittleEndian.PutUint32(tmp[:4], tx.LockTime)
	buf = append(buf, tmp[:4]...)

	// Not ANYONECANPAY: include all four cross-input commitments.
	buf = append(buf, shaPrevouts[:]...)
	buf = append(buf, shaAmounts[:]...)
	buf = append(buf, shaScriptPubKey[:]...)
	buf = append(buf, shaSequences[:]...)

	// Not NONE / not SINGLE: include shaOutputs.
	buf = append(buf, shaOutputs[:]...)

	// spend_type: bit0=annex (0), bit1=ext-flag (0 for key-path).
	buf = append(buf, 0x00)

	// Not ANYONECANPAY: commit to input index only (not outpoint/amount/etc.).
	binary.LittleEndian.PutUint32(tmp[:4], uint32(inputIdx))
	buf = append(buf, tmp[:4]...)

	// SIGHASH_SINGLE outputs are not supported here, so we skip sha_single_output.
	// Annex is not supported, so we skip sha_annex.

	return crypto.TaggedHash("TapSighash", buf), nil
}

// CalcTapScriptSigHash computes the BIP-342 signature hash for a taproot
// script-path spend. It is the BIP-341 key-path preimage with ext_flag=1,
// followed by three extra fields:
//   tapleaf_hash (32)          — TapLeaf over the executing script
//   key_version (1, 0x00)      — 0 for default tapscript version
//   codesep_position (4 LE)    — 0xFFFFFFFF when OP_CODESEPARATOR is unused
//
// Like the key-path version, the preimage is wrapped in TaggedHash("TapSighash", ...)
// and prefixed with chainID for cross-chain replay protection.
func CalcTapScriptSigHash(
	tx *primitives.Transaction,
	inputIdx int,
	prevoutScripts [][]byte,
	prevoutAmounts []int64,
	hashType byte,
	tapLeafHash [32]byte,
	chainID uint32,
) ([32]byte, error) {
	if inputIdx < 0 || inputIdx >= len(tx.Inputs) {
		return [32]byte{}, fmt.Errorf("tapscript sighash: input index %d out of range", inputIdx)
	}
	if len(prevoutScripts) != len(tx.Inputs) || len(prevoutAmounts) != len(tx.Inputs) {
		return [32]byte{}, errors.New("tapscript sighash: prevout vectors must match input count")
	}
	if hashType != sigHashDefault && hashType != sigHashAll {
		return [32]byte{}, fmt.Errorf("tapscript sighash: unsupported hash type 0x%02x", hashType)
	}

	// Reuse the key-path preimage computation and then append the
	// script-path-specific fields. We rebuild here instead of factoring out
	// a shared helper to keep the two functions' formats easy to audit
	// against BIP-341/BIP-342 line-by-line.
	var tmp [8]byte
	var shaPrevouts, shaAmounts, shaScriptPubKey, shaSequences, shaOutputs [32]byte
	{
		var buf []byte
		for _, in := range tx.Inputs {
			buf = append(buf, in.PreviousOutput.TxID[:]...)
			binary.LittleEndian.PutUint32(tmp[:4], in.PreviousOutput.Index)
			buf = append(buf, tmp[:4]...)
		}
		shaPrevouts = sha256.Sum256(buf)
	}
	{
		var buf []byte
		for _, amt := range prevoutAmounts {
			binary.LittleEndian.PutUint64(tmp[:8], uint64(amt))
			buf = append(buf, tmp[:8]...)
		}
		shaAmounts = sha256.Sum256(buf)
	}
	{
		var buf []byte
		for _, s := range prevoutScripts {
			buf = append(buf, primitives.EncodeVarIntPub(uint64(len(s)))...)
			buf = append(buf, s...)
		}
		shaScriptPubKey = sha256.Sum256(buf)
	}
	{
		var buf []byte
		for _, in := range tx.Inputs {
			binary.LittleEndian.PutUint32(tmp[:4], in.Sequence)
			buf = append(buf, tmp[:4]...)
		}
		shaSequences = sha256.Sum256(buf)
	}
	{
		var buf []byte
		for _, out := range tx.Outputs {
			binary.LittleEndian.PutUint64(tmp[:8], uint64(out.Value))
			buf = append(buf, tmp[:8]...)
			buf = append(buf, primitives.EncodeVarIntPub(uint64(len(out.ScriptPubKey)))...)
			buf = append(buf, out.ScriptPubKey...)
		}
		shaOutputs = sha256.Sum256(buf)
	}

	buf := make([]byte, 0, 320)
	binary.LittleEndian.PutUint32(tmp[:4], chainID)
	buf = append(buf, tmp[:4]...)
	buf = append(buf, 0x00) // epoch
	buf = append(buf, hashType)
	binary.LittleEndian.PutUint32(tmp[:4], tx.Version)
	buf = append(buf, tmp[:4]...)
	binary.LittleEndian.PutUint32(tmp[:4], tx.LockTime)
	buf = append(buf, tmp[:4]...)
	buf = append(buf, shaPrevouts[:]...)
	buf = append(buf, shaAmounts[:]...)
	buf = append(buf, shaScriptPubKey[:]...)
	buf = append(buf, shaSequences[:]...)
	buf = append(buf, shaOutputs[:]...)

	// spend_type: bit0=annex(0), bit1=ext-flag(1 for script-path)  → 0x02
	buf = append(buf, 0x02)
	binary.LittleEndian.PutUint32(tmp[:4], uint32(inputIdx))
	buf = append(buf, tmp[:4]...)

	// Script-path suffix (BIP-342):
	buf = append(buf, tapLeafHash[:]...)
	buf = append(buf, 0x00) // key_version (0 for tapscript v0xc0)
	binary.LittleEndian.PutUint32(tmp[:4], 0xFFFFFFFF)
	buf = append(buf, tmp[:4]...) // codesep_position

	return crypto.TaggedHash("TapSighash", buf), nil
}

// CalcSigHashWitnessV0 computes the BIP-143 signature hash for a SegWit v0
// input. The preimage is:
//   chainID (4 LE)                -- Malairt replay protection (same as legacy)
//   nVersion (4 LE)
//   hashPrevouts (32)             -- Hash256 over concatenation of all
//                                    (prevTxId || prevIndex) for every input
//   hashSequence (32)             -- Hash256 over concatenation of every
//                                    nSequence (4 LE)
//   outpoint (36)                 -- this input's prevTxId + prevIndex
//   scriptCode (varint + bytes)   -- for P2WPKH: the P2PKH script of the pkh
//   amount (8 LE)                 -- value of the output being spent
//   nSequence (4 LE)              -- this input's sequence
//   hashOutputs (32)              -- Hash256 over serialized outputs
//   nLocktime (4 LE)
//   sighashType (4 LE)            -- 0x01 (SIGHASH_ALL)
//
// BIP-143's hashPrevouts / hashSequence / hashOutputs amortise cost across
// inputs by letting verifiers cache these subhashes within a transaction.
// Amount is mixed in so a miner cannot replace the spent UTXO with a
// differently-valued one — a class of bug that the legacy sighash permits.
func CalcSigHashWitnessV0(tx *primitives.Transaction, inputIdx int, scriptCode []byte, amount int64, chainID uint32) [32]byte {
	var tmp [8]byte

	// hashPrevouts: Hash256(prevTxId || prevIndex for each input)
	hashPrevouts := func() [32]byte {
		var buf []byte
		for _, in := range tx.Inputs {
			buf = append(buf, in.PreviousOutput.TxID[:]...)
			binary.LittleEndian.PutUint32(tmp[:4], in.PreviousOutput.Index)
			buf = append(buf, tmp[:4]...)
		}
		return crypto.Hash256(buf)
	}()

	// hashSequence: Hash256(nSequence for each input)
	hashSequence := func() [32]byte {
		var buf []byte
		for _, in := range tx.Inputs {
			binary.LittleEndian.PutUint32(tmp[:4], in.Sequence)
			buf = append(buf, tmp[:4]...)
		}
		return crypto.Hash256(buf)
	}()

	// hashOutputs: Hash256(serialized outputs)
	hashOutputs := func() [32]byte {
		var buf []byte
		for _, out := range tx.Outputs {
			binary.LittleEndian.PutUint64(tmp[:8], uint64(out.Value))
			buf = append(buf, tmp[:8]...)
			buf = append(buf, primitives.EncodeVarIntPub(uint64(len(out.ScriptPubKey)))...)
			buf = append(buf, out.ScriptPubKey...)
		}
		return crypto.Hash256(buf)
	}()

	buf := make([]byte, 0, 200)

	// chainID (4 LE) — Malairt addition for cross-chain replay protection.
	binary.LittleEndian.PutUint32(tmp[:4], chainID)
	buf = append(buf, tmp[:4]...)

	// nVersion (4 LE)
	binary.LittleEndian.PutUint32(tmp[:4], tx.Version)
	buf = append(buf, tmp[:4]...)

	// hashPrevouts, hashSequence
	buf = append(buf, hashPrevouts[:]...)
	buf = append(buf, hashSequence[:]...)

	// outpoint (36)
	in := tx.Inputs[inputIdx]
	buf = append(buf, in.PreviousOutput.TxID[:]...)
	binary.LittleEndian.PutUint32(tmp[:4], in.PreviousOutput.Index)
	buf = append(buf, tmp[:4]...)

	// scriptCode (varint + bytes)
	buf = append(buf, primitives.EncodeVarIntPub(uint64(len(scriptCode)))...)
	buf = append(buf, scriptCode...)

	// amount (8 LE)
	binary.LittleEndian.PutUint64(tmp[:8], uint64(amount))
	buf = append(buf, tmp[:8]...)

	// nSequence (4 LE)
	binary.LittleEndian.PutUint32(tmp[:4], in.Sequence)
	buf = append(buf, tmp[:4]...)

	// hashOutputs
	buf = append(buf, hashOutputs[:]...)

	// nLocktime (4 LE)
	binary.LittleEndian.PutUint32(tmp[:4], tx.LockTime)
	buf = append(buf, tmp[:4]...)

	// sighashType (4 LE) — currently only SIGHASH_ALL supported
	binary.LittleEndian.PutUint32(tmp[:4], uint32(sigHashAll))
	buf = append(buf, tmp[:4]...)

	return crypto.Hash256(buf)
}
