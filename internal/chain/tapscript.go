package chain

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/computervirtualservices/malairte/internal/crypto"
	"github.com/computervirtualservices/malairte/internal/primitives"
)

// Control block layout per BIP-341 §Verification of taproot output:
//   byte 0:        (leafVersion & 0xfe) | (parity & 0x01)
//   bytes 1..33:   32-byte x-only internal key P
//   bytes 33..33+32m: m siblings, each 32 bytes, where m is the leaf's
//                  merkle path length. Maximum m is 128.
const (
	// tapCtrlBlockMinLen is 33 bytes: byte0 + internal key with m=0 (a tree
	// consisting of a single leaf — no siblings needed).
	tapCtrlBlockMinLen = 33
	// tapCtrlBlockMaxPathLen is the BIP-341 max tree depth.
	tapCtrlBlockMaxPathLen = 128
)

// controlBlock is a parsed BIP-341 control block.
type controlBlock struct {
	LeafVersion byte
	OutputParity byte // 0 = even y, 1 = odd y
	InternalKey []byte
	MerklePath  [][32]byte
}

// parseControlBlock validates the structural constraints and splits a raw
// control block into its components. It does NOT verify the merkle
// commitment — that is verifyTaprootCommitment's job.
func parseControlBlock(cb []byte) (*controlBlock, error) {
	if len(cb) < tapCtrlBlockMinLen {
		return nil, fmt.Errorf("tapscript: control block length %d < min %d", len(cb), tapCtrlBlockMinLen)
	}
	// Path portion must be an integer multiple of 32 bytes.
	pathBytes := len(cb) - tapCtrlBlockMinLen
	if pathBytes%32 != 0 {
		return nil, fmt.Errorf("tapscript: control block path %d not a multiple of 32", pathBytes)
	}
	pathLen := pathBytes / 32
	if pathLen > tapCtrlBlockMaxPathLen {
		return nil, fmt.Errorf("tapscript: merkle path depth %d exceeds max %d", pathLen, tapCtrlBlockMaxPathLen)
	}

	out := &controlBlock{
		LeafVersion:  cb[0] & 0xfe,
		OutputParity: cb[0] & 0x01,
		InternalKey:  make([]byte, 32),
		MerklePath:   make([][32]byte, pathLen),
	}
	copy(out.InternalKey, cb[1:33])
	for i := 0; i < pathLen; i++ {
		copy(out.MerklePath[i][:], cb[33+32*i:33+32*(i+1)])
	}
	return out, nil
}

// verifyTaprootCommitment checks that the internal key, merkle path, and leaf
// hash together commit to outputKey (the 32-byte x-only key in the P2TR
// scriptPubKey). Returns nil on success, an error explaining the failure
// otherwise. Parity of the reconstructed output key must match the parity
// bit in the control block.
func verifyTaprootCommitment(cb *controlBlock, leafHash [32]byte, outputKey []byte) error {
	// Walk the merkle path from leaf to root.
	root := leafHash
	for _, sib := range cb.MerklePath {
		root = crypto.TapBranchHash(root, sib)
	}

	// Tweak the internal key by the computed merkle root.
	tweaked, oddY, err := crypto.TapTweakPubKey(cb.InternalKey, root[:])
	if err != nil {
		return fmt.Errorf("tapscript: tweak failed: %w", err)
	}
	gotParity := byte(0)
	if oddY {
		gotParity = 1
	}
	if gotParity != cb.OutputParity {
		return errors.New("tapscript: output-key parity mismatch")
	}
	if len(tweaked) != 32 || len(outputKey) != 32 {
		return errors.New("tapscript: internal size invariant broken")
	}
	for i := 0; i < 32; i++ {
		if tweaked[i] != outputKey[i] {
			return errors.New("tapscript: tweaked internal key does not match output key")
		}
	}
	return nil
}

// ── Minimum-viable BIP-342 tapscript interpreter ─────────────────────────────
//
// Supports the opcode subset required by single-sig, multisig-via-CHECKSIGADD,
// and common hashlock patterns. Fully compliant with BIP-342 for the opcodes
// listed below; disabled opcodes fail; all other opcodes fail hard (no
// OP_SUCCESS forward-compat slot yet — that can be added in a follow-up that
// carefully reserves ranges for future soft forks).

// executeTapScript interprets script against the given initial stack.
// stackInputs carries every witness item BEFORE the script and control
// block — these are the "script arguments" pushed onto the stack before
// interpretation starts. Returns nil iff the script ends with exactly one
// truthy item on the stack.
func executeTapScript(
	script []byte,
	stackInputs [][]byte,
	tx *primitives.Transaction,
	inputIdx int,
	prevoutScripts [][]byte,
	prevoutAmounts []int64,
	tapLeafHash [32]byte,
	chainID uint32,
) error {
	stack := append([][]byte{}, stackInputs...)
	pos := 0

	for pos < len(script) {
		op := script[pos]
		pos++

		// Data-push opcodes.
		if op == 0x00 {
			stack = append(stack, []byte{})
			continue
		}
		if op >= 0x01 && op <= 0x4b {
			n := int(op)
			if pos+n > len(script) {
				return errors.New("tapscript: truncated direct push")
			}
			stack = append(stack, append([]byte(nil), script[pos:pos+n]...))
			pos += n
			continue
		}
		switch op {
		case 0x4c: // OP_PUSHDATA1
			if pos+1 > len(script) {
				return errors.New("tapscript: truncated PUSHDATA1 length")
			}
			n := int(script[pos])
			pos++
			if pos+n > len(script) {
				return errors.New("tapscript: truncated PUSHDATA1")
			}
			stack = append(stack, append([]byte(nil), script[pos:pos+n]...))
			pos += n
			continue
		case 0x4d: // OP_PUSHDATA2
			if pos+2 > len(script) {
				return errors.New("tapscript: truncated PUSHDATA2 length")
			}
			n := int(binary.LittleEndian.Uint16(script[pos : pos+2]))
			pos += 2
			if pos+n > len(script) {
				return errors.New("tapscript: truncated PUSHDATA2")
			}
			stack = append(stack, append([]byte(nil), script[pos:pos+n]...))
			pos += n
			continue
		case 0x4e: // OP_PUSHDATA4
			if pos+4 > len(script) {
				return errors.New("tapscript: truncated PUSHDATA4 length")
			}
			n := int(binary.LittleEndian.Uint32(script[pos : pos+4]))
			pos += 4
			if pos+n > len(script) {
				return errors.New("tapscript: truncated PUSHDATA4")
			}
			stack = append(stack, append([]byte(nil), script[pos:pos+n]...))
			pos += n
			continue
		case 0x4f: // OP_1NEGATE
			stack = append(stack, []byte{0x81})
			continue
		}
		if op >= 0x51 && op <= 0x60 { // OP_1..OP_16
			stack = append(stack, []byte{op - 0x50})
			continue
		}

		// Non-push opcodes.
		switch op {
		case 0x61: // OP_NOP
			// Intentionally blank.
		case 0x69: // OP_VERIFY
			v, err := tapPop(&stack)
			if err != nil {
				return err
			}
			if !tapTruthy(v) {
				return errors.New("tapscript: OP_VERIFY failed")
			}
		case 0x75: // OP_DROP
			if _, err := tapPop(&stack); err != nil {
				return err
			}
		case 0x76: // OP_DUP
			if len(stack) < 1 {
				return errors.New("tapscript: OP_DUP on empty stack")
			}
			top := stack[len(stack)-1]
			stack = append(stack, append([]byte(nil), top...))
		case 0x7c: // OP_SWAP
			if len(stack) < 2 {
				return errors.New("tapscript: OP_SWAP needs 2 items")
			}
			stack[len(stack)-1], stack[len(stack)-2] = stack[len(stack)-2], stack[len(stack)-1]
		case 0x87: // OP_EQUAL
			a, err := tapPop(&stack)
			if err != nil {
				return err
			}
			b, err := tapPop(&stack)
			if err != nil {
				return err
			}
			if bytes.Equal(a, b) {
				stack = append(stack, []byte{0x01})
			} else {
				stack = append(stack, []byte{})
			}
		case 0x88: // OP_EQUALVERIFY
			a, err := tapPop(&stack)
			if err != nil {
				return err
			}
			b, err := tapPop(&stack)
			if err != nil {
				return err
			}
			if !bytes.Equal(a, b) {
				return errors.New("tapscript: OP_EQUALVERIFY failed")
			}
		case 0xa8: // OP_SHA256
			v, err := tapPop(&stack)
			if err != nil {
				return err
			}
			h := sha256.Sum256(v)
			stack = append(stack, h[:])
		case 0xa9: // OP_HASH160
			v, err := tapPop(&stack)
			if err != nil {
				return err
			}
			h := crypto.Hash160(v)
			stack = append(stack, h[:])
		case 0xaa: // OP_HASH256
			v, err := tapPop(&stack)
			if err != nil {
				return err
			}
			h := crypto.Hash256(v)
			stack = append(stack, h[:])
		case 0xac: // OP_CHECKSIG
			pk, err := tapPop(&stack)
			if err != nil {
				return err
			}
			sig, err := tapPop(&stack)
			if err != nil {
				return err
			}
			ok, err := tapscriptCheckSig(sig, pk, tx, inputIdx, prevoutScripts, prevoutAmounts, tapLeafHash, chainID)
			if err != nil {
				return err
			}
			if ok {
				stack = append(stack, []byte{0x01})
			} else {
				stack = append(stack, []byte{})
			}
		case 0xad: // OP_CHECKSIGVERIFY
			pk, err := tapPop(&stack)
			if err != nil {
				return err
			}
			sig, err := tapPop(&stack)
			if err != nil {
				return err
			}
			ok, err := tapscriptCheckSig(sig, pk, tx, inputIdx, prevoutScripts, prevoutAmounts, tapLeafHash, chainID)
			if err != nil {
				return err
			}
			if !ok {
				return errors.New("tapscript: OP_CHECKSIGVERIFY failed")
			}
		case 0xba: // OP_CHECKSIGADD (BIP-342)
			pk, err := tapPop(&stack)
			if err != nil {
				return err
			}
			nBytes, err := tapPop(&stack)
			if err != nil {
				return err
			}
			sig, err := tapPop(&stack)
			if err != nil {
				return err
			}
			n, err := tapScriptNumToInt(nBytes)
			if err != nil {
				return fmt.Errorf("tapscript: OP_CHECKSIGADD: %w", err)
			}
			ok, err := tapscriptCheckSig(sig, pk, tx, inputIdx, prevoutScripts, prevoutAmounts, tapLeafHash, chainID)
			if err != nil {
				return err
			}
			if ok {
				n++
			}
			stack = append(stack, tapIntToScriptNum(n))
		case 0xb1: // OP_CHECKLOCKTIMEVERIFY (BIP-65)
			// Peek (don't pop) the top, interpret as a script number, and
			// require tx.LockTime ≥ it. Both must be the same "type" —
			// <500_000_000 = block height, ≥500_000_000 = unix timestamp.
			if len(stack) < 1 {
				return errors.New("tapscript: OP_CLTV on empty stack")
			}
			top := stack[len(stack)-1]
			locktime, err := tapScriptNumToInt(top)
			if err != nil {
				return fmt.Errorf("tapscript: OP_CLTV: %w", err)
			}
			if locktime < 0 {
				return errors.New("tapscript: OP_CLTV requires non-negative operand")
			}
			// Type mismatch: height vs timestamp domain must match.
			const locktimeThreshold = int64(500_000_000)
			txLock := int64(tx.LockTime)
			if (locktime < locktimeThreshold) != (txLock < locktimeThreshold) {
				return errors.New("tapscript: OP_CLTV locktime/txLockTime type mismatch")
			}
			if txLock < locktime {
				return fmt.Errorf("tapscript: OP_CLTV not satisfied: require %d, have %d",
					locktime, txLock)
			}
			// Also require the input's sequence to be non-final (< 0xFFFFFFFF)
			// — otherwise locktime has no effect.
			if tx.Inputs[inputIdx].Sequence == 0xFFFFFFFF {
				return errors.New("tapscript: OP_CLTV requires non-final sequence")
			}
		case 0xb2: // OP_CHECKSEQUENCEVERIFY (BIP-112)
			// Peek top, interpret as sequence-encoded relative timelock,
			// require tx.Version ≥ 2 AND input.Sequence satisfies the
			// relative delay in the same way BIP-68 validates at tx level.
			if len(stack) < 1 {
				return errors.New("tapscript: OP_CSV on empty stack")
			}
			top := stack[len(stack)-1]
			csvSeq, err := tapScriptNumToInt(top)
			if err != nil {
				return fmt.Errorf("tapscript: OP_CSV: %w", err)
			}
			if csvSeq < 0 {
				return errors.New("tapscript: OP_CSV requires non-negative operand")
			}
			// If the disable flag is set in the operand, OP_CSV is a no-op.
			const seqDisable = int64(1) << 31
			if csvSeq&seqDisable != 0 {
				// OP_CSV fires but passes silently (reserved upgradeability).
				break
			}
			if tx.Version < 2 {
				return errors.New("tapscript: OP_CSV requires tx.Version ≥ 2")
			}
			inSeq := int64(tx.Inputs[inputIdx].Sequence)
			if inSeq&seqDisable != 0 {
				return errors.New("tapscript: OP_CSV: input sequence has disable flag")
			}
			const seqType = int64(1) << 22
			if (csvSeq & seqType) != (inSeq & seqType) {
				return errors.New("tapscript: OP_CSV: type (block/time) mismatch")
			}
			const seqMask = int64(0x0000ffff)
			if (inSeq & seqMask) < (csvSeq & seqMask) {
				return fmt.Errorf("tapscript: OP_CSV not satisfied: require %d, have %d",
					csvSeq&seqMask, inSeq&seqMask)
			}
		case 0xb3: // OP_CHECKTEMPLATEVERIFY (BIP-119)
			// Pop a 32-byte "standard template hash" from the stack and
			// require that the spending transaction's shape (at inputIdx)
			// matches it bit-for-bit. The template hash commits to
			// nVersion, nLockTime, scriptSigs, sequences, outputs, and
			// the input index — so the UTXO's script can mandate exactly
			// how it may be spent (vaults, congestion-control payouts,
			// payment pools, etc).
			//
			// BIP-119 says: if the operand is NOT 32 bytes, treat OP_CTV
			// as OP_NOP4 (succeed silently) so older scripts can ignore
			// it. We follow that upgradeability rule.
			if len(stack) < 1 {
				return errors.New("tapscript: OP_CTV on empty stack")
			}
			templateHash := stack[len(stack)-1]
			if len(templateHash) != 32 {
				// OP_NOP4 semantics — silent success.
				break
			}
			got := standardTemplateHash(tx, inputIdx)
			if !bytes.Equal(got[:], templateHash) {
				return fmt.Errorf("tapscript: OP_CTV template mismatch: got %x want %x",
					got, templateHash)
			}
		case 0xae, 0xaf:
			return errors.New("tapscript: OP_CHECKMULTISIG[VERIFY] disabled in tapscript")
		default:
			return fmt.Errorf("tapscript: unsupported opcode 0x%02x", op)
		}
	}

	if len(stack) != 1 {
		return fmt.Errorf("tapscript: stack size after execution = %d, want 1", len(stack))
	}
	if !tapTruthy(stack[0]) {
		return errors.New("tapscript: final stack top not truthy")
	}
	return nil
}

// tapscriptCheckSig is the BIP-342 CHECKSIG semantic. An empty signature is a
// "this participant didn't sign" marker and never fails the script — it just
// reports "not valid". A non-empty signature that fails to verify causes the
// entire script to fail (BIP-342's nullfail rule).
func tapscriptCheckSig(
	sig, pk []byte,
	tx *primitives.Transaction,
	inputIdx int,
	prevoutScripts [][]byte,
	prevoutAmounts []int64,
	tapLeafHash [32]byte,
	chainID uint32,
) (bool, error) {
	if len(sig) == 0 {
		return false, nil
	}
	if len(pk) == 0 {
		return false, errors.New("tapscript: empty pubkey with non-empty sig")
	}
	if len(pk) != 32 {
		// Strict 32-byte policy for now. BIP-342 treats unknown lengths as
		// "unknown pubkey type — always valid" for soft-fork upgradeability;
		// we can relax once a use case appears.
		return false, fmt.Errorf("tapscript: pubkey must be 32 bytes, got %d", len(pk))
	}

	var hashType byte
	var sigBytes []byte
	switch len(sig) {
	case 64:
		hashType = sigHashDefault
		sigBytes = sig
	case 65:
		if sig[64] == sigHashDefault {
			return false, errors.New("tapscript: explicit SIGHASH_DEFAULT (0x00) is invalid")
		}
		hashType = sig[64]
		sigBytes = sig[:64]
	default:
		return false, fmt.Errorf("tapscript: sig must be 64 or 65 bytes, got %d", len(sig))
	}

	sigHash, err := CalcTapScriptSigHash(tx, inputIdx, prevoutScripts, prevoutAmounts, hashType, tapLeafHash, chainID)
	if err != nil {
		return false, err
	}
	return crypto.SchnorrVerify(pk, sigHash[:], sigBytes), nil
}

// tapPop removes and returns the top of the stack.
func tapPop(stack *[][]byte) ([]byte, error) {
	if len(*stack) == 0 {
		return nil, errors.New("tapscript: pop from empty stack")
	}
	v := (*stack)[len(*stack)-1]
	*stack = (*stack)[:len(*stack)-1]
	return v, nil
}

// tapTruthy applies Bitcoin's "cast to bool" rule: the value is false iff
// every byte is 0, except the high bit of the last byte may be set (that
// encodes negative-zero, which is also false). Everything else is true.
func tapTruthy(v []byte) bool {
	for i, b := range v {
		if b == 0 {
			continue
		}
		if i == len(v)-1 && b == 0x80 {
			return false
		}
		return true
	}
	return false
}

// tapScriptNumToInt decodes a tapscript number. Tapscript enforces minimal
// encoding (BIP-342): trailing 0x00 / 0x80 bytes that could be stripped
// must have been stripped by the producer.
func tapScriptNumToInt(v []byte) (int64, error) {
	if len(v) > 4 {
		return 0, fmt.Errorf("number too large (%d bytes)", len(v))
	}
	if len(v) == 0 {
		return 0, nil
	}
	if v[len(v)-1]&0x7f == 0 && (len(v) <= 1 || v[len(v)-2]&0x80 == 0) {
		return 0, errors.New("non-minimally-encoded number")
	}

	var result int64
	for i, b := range v {
		if i == len(v)-1 {
			if b&0x80 != 0 {
				result |= int64(b&0x7f) << (8 * i)
				return -result, nil
			}
			result |= int64(b) << (8 * i)
			return result, nil
		}
		result |= int64(b) << (8 * i)
	}
	return result, nil
}

// standardTemplateHash computes the BIP-119 StandardTemplateHash for tx at
// inputIdx. Deterministic — same tx + same inputIdx always produces the
// same 32 bytes. Callers compute this at coin-creation time to compile a
// covenant into a scriptPubKey; spenders must present a tx that hashes to
// the same value.
//
// Layout (all little-endian integers; SHA256 inputs/outputs as 32 bytes):
//
//   nVersion (4)
//   nLockTime (4)
//   scriptSigs_hash (32)  // SHA256 of concat of all scriptSig byte strings
//                         // with length prefixes, or 32 zero bytes if all empty
//   inputCount (4)
//   sequences_hash (32)   // SHA256 of concat of all nSequence (4 LE each)
//   outputCount (4)
//   outputs_hash (32)     // SHA256 of concat of CTxOut serializations
//   inputIndex (4)
//
// The final hash is a single SHA256 (NOT double) per BIP-119.
func standardTemplateHash(tx *primitives.Transaction, inputIdx int) [32]byte {
	var tmp [8]byte

	// scriptSigs_hash: omit if every scriptSig is empty (common for all-
	// taproot spends). Per BIP-119, the zero vector case commits to the
	// SHA256 of an empty-length-prefix-only concat. Simplest to hash the
	// length-prefixed concat unconditionally.
	var ssBuf []byte
	allEmpty := true
	for _, in := range tx.Inputs {
		ssBuf = append(ssBuf, primitives.EncodeVarIntPub(uint64(len(in.ScriptSig)))...)
		ssBuf = append(ssBuf, in.ScriptSig...)
		if len(in.ScriptSig) != 0 {
			allEmpty = false
		}
	}
	var scriptSigsHash [32]byte
	if !allEmpty {
		scriptSigsHash = sha256sum(ssBuf)
	}

	// sequences_hash
	var seqBuf []byte
	for _, in := range tx.Inputs {
		binary.LittleEndian.PutUint32(tmp[:4], in.Sequence)
		seqBuf = append(seqBuf, tmp[:4]...)
	}
	seqHash := sha256sum(seqBuf)

	// outputs_hash
	var outBuf []byte
	for _, out := range tx.Outputs {
		binary.LittleEndian.PutUint64(tmp[:8], uint64(out.Value))
		outBuf = append(outBuf, tmp[:8]...)
		outBuf = append(outBuf, primitives.EncodeVarIntPub(uint64(len(out.ScriptPubKey)))...)
		outBuf = append(outBuf, out.ScriptPubKey...)
	}
	outHash := sha256sum(outBuf)

	buf := make([]byte, 0, 4+4+32+4+32+4+32+4)
	binary.LittleEndian.PutUint32(tmp[:4], tx.Version)
	buf = append(buf, tmp[:4]...)
	binary.LittleEndian.PutUint32(tmp[:4], tx.LockTime)
	buf = append(buf, tmp[:4]...)
	buf = append(buf, scriptSigsHash[:]...)
	binary.LittleEndian.PutUint32(tmp[:4], uint32(len(tx.Inputs)))
	buf = append(buf, tmp[:4]...)
	buf = append(buf, seqHash[:]...)
	binary.LittleEndian.PutUint32(tmp[:4], uint32(len(tx.Outputs)))
	buf = append(buf, tmp[:4]...)
	buf = append(buf, outHash[:]...)
	binary.LittleEndian.PutUint32(tmp[:4], uint32(inputIdx))
	buf = append(buf, tmp[:4]...)

	return sha256sum(buf)
}

func sha256sum(b []byte) [32]byte {
	return sha256.Sum256(b)
}

// tapIntToScriptNum encodes an int64 as a minimally-encoded script number.
func tapIntToScriptNum(n int64) []byte {
	if n == 0 {
		return []byte{}
	}
	neg := n < 0
	abs := n
	if neg {
		abs = -n
	}
	out := []byte{}
	for abs > 0 {
		out = append(out, byte(abs&0xff))
		abs >>= 8
	}
	if out[len(out)-1]&0x80 != 0 {
		if neg {
			out = append(out, 0x80)
		} else {
			out = append(out, 0x00)
		}
	} else if neg {
		out[len(out)-1] |= 0x80
	}
	return out
}
