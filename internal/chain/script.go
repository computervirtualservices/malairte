package chain

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/malairt/malairt/internal/crypto"
	"github.com/malairt/malairt/internal/primitives"
)

// sigHashAll is the only supported SIGHASH type: sign all inputs and outputs.
const sigHashAll byte = 0x01

// ExecuteScript verifies scriptSig (input unlocking script) against scriptPubKey
// (UTXO locking script) for the input at inputIdx inside tx.
//
// Currently supports P2PKH scripts only. Any non-P2PKH scriptPubKey is passed
// permissively until a full script interpreter is implemented.
func ExecuteScript(scriptSig, scriptPubKey []byte, tx *primitives.Transaction, inputIdx int) error {
	if primitives.IsP2PKHScript(scriptPubKey) {
		return executeP2PKH(scriptSig, scriptPubKey, tx, inputIdx)
	}
	// Non-P2PKH: permissive until full interpreter is in place
	return nil
}

// executeP2PKH implements the six-step P2PKH verification shortcut:
//  1. Parse <sig> and <pubkey> from scriptSig.
//  2. Verify Hash160(pubkey) == expectedHash from scriptPubKey (OP_HASH160 + OP_EQUALVERIFY).
//  3. Strip the sighash-type byte and recompute the transaction signature hash.
//  4. Verify the DER-encoded ECDSA signature (OP_CHECKSIG).
func executeP2PKH(scriptSig, scriptPubKey []byte, tx *primitives.Transaction, inputIdx int) error {
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
	sigHash := calcSigHash(tx, inputIdx, scriptPubKey)
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
// the on-chain validator's expectations.
func CalcSigHash(tx *primitives.Transaction, inputIdx int, subscript []byte) [32]byte {
	return calcSigHash(tx, inputIdx, subscript)
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
// Bitcoin SIGHASH_ALL serialization:
//   - version (4 bytes LE)
//   - varint(inputCount) + inputs: TxID(32) + index(4) + scriptSig(subscript for
//     inputIdx, empty for all others) + sequence(4)
//   - varint(outputCount) + outputs: value(8) + scriptPubKey
//   - locktime (4 bytes LE)
//   - hashType (4 bytes LE, 0x00000001 for SIGHASH_ALL)
//
// Returns Hash256 (double-SHA256) of the resulting byte slice.
func calcSigHash(tx *primitives.Transaction, inputIdx int, subscript []byte) [32]byte {
	buf := make([]byte, 0, 256)
	var tmp [8]byte

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
