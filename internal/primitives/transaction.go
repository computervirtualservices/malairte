package primitives

import (
	"bytes"
	"encoding/binary"

	"github.com/computervirtualservices/malairte/internal/crypto"
)

// OutPoint identifies a specific output of a specific transaction.
type OutPoint struct {
	TxID  [32]byte
	Index uint32
}

// TxInput spends a previous output.
//
// Witness is the BIP-141 witness stack for this input: a list of byte-strings
// that SegWit script templates consume in place of (or in addition to) the
// legacy ScriptSig. Legacy P2PKH inputs carry an empty (or nil) witness; a
// P2WPKH input leaves ScriptSig empty and carries the signature and pubkey in
// Witness. Serialization always emits the witness section, so nil and empty
// slices produce the same on-wire bytes.
type TxInput struct {
	PreviousOutput OutPoint
	ScriptSig      []byte
	Sequence       uint32
	Witness        [][]byte
}

// TxOutput is a new output being created.
type TxOutput struct {
	Value        int64  // atoms (1 MLRT = 100_000_000 atoms)
	ScriptPubKey []byte // P2PKH or similar
}

// Transaction holds inputs and outputs.
// Version 1 is the current transaction version.
type Transaction struct {
	Version  uint32
	Inputs   []TxInput
	Outputs  []TxOutput
	LockTime uint32
}

// TxID returns Hash256(tx.SerializeBase()) — the transaction ID.
// The base serialization omits marker, flag, and witness bytes so that
// malleating a signature (i.e. editing the witness stack) does not change the
// txid. Coinbase inputs have PreviousOutput = OutPoint{TxID: [32]byte{}, Index: 0xFFFFFFFF}.
func (tx *Transaction) TxID() [32]byte {
	return crypto.Hash256(tx.SerializeBase())
}

// WTxID returns the BIP-141 witness transaction id. For non-coinbase txs it is
// Hash256 over the full segwit serialization (marker + flag + witness), so it
// differs from TxID whenever any input carries a non-empty witness stack. For
// the coinbase BIP-141 hard-codes WTxID = 0x00…00 to avoid the self-reference
// problem created by placing the witness commitment inside the coinbase itself.
func (tx *Transaction) WTxID() [32]byte {
	if tx.IsCoinbase() {
		return [32]byte{}
	}
	return crypto.Hash256(tx.Serialize())
}

// IsCoinbase returns true if the first input is a coinbase input.
// A coinbase input is identified by PreviousOutput.Index == 0xFFFFFFFF
// and an all-zeros TxID.
func (tx *Transaction) IsCoinbase() bool {
	if len(tx.Inputs) == 0 {
		return false
	}
	in := tx.Inputs[0]
	return in.PreviousOutput.Index == 0xFFFFFFFF &&
		in.PreviousOutput.TxID == ([32]byte{})
}

// BaseSize returns the length of SerializeBase(): the transaction without any
// witness data. This is the non-witness byte count used in weight calculations
// and is what TxID hashes over.
func (tx *Transaction) BaseSize() int {
	return len(tx.SerializeBase())
}

// TotalSize returns the length of the full Serialize() output (SegWit format,
// including marker, flag, and every input's witness stack).
func (tx *Transaction) TotalSize() int {
	return len(tx.Serialize())
}

// Weight returns the transaction's consensus weight in weight units (WU),
// computed as BIP-141 prescribes:
//   weight = baseSize * WitnessScaleFactor + (totalSize - baseSize)
// Witness bytes contribute 1 WU each; every other byte contributes
// WitnessScaleFactor (=4) WU.
func (tx *Transaction) Weight() int {
	base := tx.BaseSize()
	total := tx.TotalSize()
	return base*WitnessScaleFactor + (total - base)
}

// SerializeBase encodes the transaction WITHOUT any segwit marker, flag, or
// witness stack. This is the format used by TxID and by legacy (BIP-143 pre-
// image) sighash calculations.
//
// Layout: version(4) | varint(inputCount) | inputs | varint(outputCount) |
//         outputs | locktime(4)
// Each input: prevTxId(32) | prevIndex(4) | varint(scriptLen) | scriptSig |
//             sequence(4)
func (tx *Transaction) SerializeBase() []byte {
	var buf bytes.Buffer
	writeTxBase(&buf, tx)
	return buf.Bytes()
}

// Serialize encodes the full transaction in SegWit wire format:
//   version(4) | 0x00 (marker) | 0x01 (flag) | inputs-section |
//   outputs-section | witness-section | locktime(4)
// The witness section contains, for each input in order, a varint item count
// followed by each item as varint(len) || bytes. Inputs with no witness data
// serialize as a single zero byte (item count = 0), so legacy inputs still
// round-trip cleanly through this format.
func (tx *Transaction) Serialize() []byte {
	var buf bytes.Buffer

	// Version (4 bytes LE)
	var versionBytes [4]byte
	binary.LittleEndian.PutUint32(versionBytes[:], tx.Version)
	buf.Write(versionBytes[:])

	// Marker + flag (SegWit). Fixed bytes: 0x00, 0x01.
	buf.WriteByte(0x00)
	buf.WriteByte(0x01)

	// Input / output sections (identical to SerializeBase minus the version
	// prefix it already wrote).
	writeTxInputsOutputs(&buf, tx)

	// Witness section: for every input, in order, write its stack as
	//   varint(count) || for each item: varint(len) || bytes
	for _, in := range tx.Inputs {
		buf.Write(encodeVarInt(uint64(len(in.Witness))))
		for _, item := range in.Witness {
			buf.Write(encodeVarInt(uint64(len(item))))
			buf.Write(item)
		}
	}

	// LockTime (4 bytes LE)
	var ltBytes [4]byte
	binary.LittleEndian.PutUint32(ltBytes[:], tx.LockTime)
	buf.Write(ltBytes[:])

	return buf.Bytes()
}

// writeTxBase writes the full non-witness serialization to buf.
func writeTxBase(buf *bytes.Buffer, tx *Transaction) {
	var versionBytes [4]byte
	binary.LittleEndian.PutUint32(versionBytes[:], tx.Version)
	buf.Write(versionBytes[:])
	writeTxInputsOutputs(buf, tx)
	var ltBytes [4]byte
	binary.LittleEndian.PutUint32(ltBytes[:], tx.LockTime)
	buf.Write(ltBytes[:])
}

// writeTxInputsOutputs writes the input and output sections of a transaction
// (everything between version and locktime, excluding marker/flag/witness).
func writeTxInputsOutputs(buf *bytes.Buffer, tx *Transaction) {
	buf.Write(encodeVarInt(uint64(len(tx.Inputs))))
	for _, in := range tx.Inputs {
		buf.Write(in.PreviousOutput.TxID[:])
		var idxBytes [4]byte
		binary.LittleEndian.PutUint32(idxBytes[:], in.PreviousOutput.Index)
		buf.Write(idxBytes[:])
		buf.Write(encodeVarInt(uint64(len(in.ScriptSig))))
		buf.Write(in.ScriptSig)
		var seqBytes [4]byte
		binary.LittleEndian.PutUint32(seqBytes[:], in.Sequence)
		buf.Write(seqBytes[:])
	}
	buf.Write(encodeVarInt(uint64(len(tx.Outputs))))
	for _, out := range tx.Outputs {
		var valBytes [8]byte
		binary.LittleEndian.PutUint64(valBytes[:], uint64(out.Value))
		buf.Write(valBytes[:])
		buf.Write(encodeVarInt(uint64(len(out.ScriptPubKey))))
		buf.Write(out.ScriptPubKey)
	}
}

// encodeVarInt encodes an unsigned integer as a Bitcoin-style variable-length integer.
// 1 byte for values < 0xFD, 3 bytes for values <= 0xFFFF,
// 5 bytes for values <= 0xFFFFFFFF, 9 bytes otherwise.
func encodeVarInt(val uint64) []byte {
	switch {
	case val < 0xFD:
		return []byte{byte(val)}
	case val <= 0xFFFF:
		b := make([]byte, 3)
		b[0] = 0xFD
		binary.LittleEndian.PutUint16(b[1:], uint16(val))
		return b
	case val <= 0xFFFFFFFF:
		b := make([]byte, 5)
		b[0] = 0xFE
		binary.LittleEndian.PutUint32(b[1:], uint32(val))
		return b
	default:
		b := make([]byte, 9)
		b[0] = 0xFF
		binary.LittleEndian.PutUint64(b[1:], val)
		return b
	}
}

// EncodeVarIntPub is the exported version of encodeVarInt for use by other packages.
func EncodeVarIntPub(val uint64) []byte {
	return encodeVarInt(val)
}

// DecodeVarInt reads a Bitcoin-style variable-length integer from a byte slice.
// Returns the decoded value and the number of bytes consumed.
func DecodeVarInt(data []byte) (uint64, int, error) {
	if len(data) == 0 {
		return 0, 0, errInvalidVarInt
	}
	switch data[0] {
	case 0xFD:
		if len(data) < 3 {
			return 0, 0, errInvalidVarInt
		}
		return uint64(binary.LittleEndian.Uint16(data[1:3])), 3, nil
	case 0xFE:
		if len(data) < 5 {
			return 0, 0, errInvalidVarInt
		}
		return uint64(binary.LittleEndian.Uint32(data[1:5])), 5, nil
	case 0xFF:
		if len(data) < 9 {
			return 0, 0, errInvalidVarInt
		}
		return binary.LittleEndian.Uint64(data[1:9]), 9, nil
	default:
		return uint64(data[0]), 1, nil
	}
}

// DeserializeTx deserializes a transaction from the SegWit wire format
// produced by Serialize(). Returns the transaction and the number of bytes
// consumed. Pure-legacy format (no marker+flag) is not supported — the chain
// has a single canonical serialization.
func DeserializeTx(data []byte) (*Transaction, int, error) {
	if len(data) < 4 {
		return nil, 0, errTooShort
	}
	pos := 0
	tx := &Transaction{}

	// Version
	tx.Version = binary.LittleEndian.Uint32(data[pos : pos+4])
	pos += 4

	// Marker + flag (mandatory).
	if pos+2 > len(data) {
		return nil, 0, errTooShort
	}
	if data[pos] != 0x00 || data[pos+1] != 0x01 {
		return nil, 0, errInvalidVarInt // marker/flag mismatch
	}
	pos += 2

	// Input count
	inputCount, n, err := DecodeVarInt(data[pos:])
	if err != nil {
		return nil, 0, err
	}
	pos += n

	// Inputs (without witness — witnesses come after outputs).
	tx.Inputs = make([]TxInput, inputCount)
	for i := uint64(0); i < inputCount; i++ {
		if pos+36 > len(data) {
			return nil, 0, errTooShort
		}
		var in TxInput
		copy(in.PreviousOutput.TxID[:], data[pos:pos+32])
		pos += 32
		in.PreviousOutput.Index = binary.LittleEndian.Uint32(data[pos : pos+4])
		pos += 4
		scriptLen, n, err := DecodeVarInt(data[pos:])
		if err != nil {
			return nil, 0, err
		}
		pos += n
		if uint64(pos)+scriptLen > uint64(len(data)) {
			return nil, 0, errTooShort
		}
		in.ScriptSig = make([]byte, scriptLen)
		copy(in.ScriptSig, data[pos:pos+int(scriptLen)])
		pos += int(scriptLen)
		if pos+4 > len(data) {
			return nil, 0, errTooShort
		}
		in.Sequence = binary.LittleEndian.Uint32(data[pos : pos+4])
		pos += 4
		tx.Inputs[i] = in
	}

	// Output count
	outputCount, n, err := DecodeVarInt(data[pos:])
	if err != nil {
		return nil, 0, err
	}
	pos += n

	// Outputs
	tx.Outputs = make([]TxOutput, outputCount)
	for i := uint64(0); i < outputCount; i++ {
		if pos+8 > len(data) {
			return nil, 0, errTooShort
		}
		var out TxOutput
		out.Value = int64(binary.LittleEndian.Uint64(data[pos : pos+8]))
		pos += 8
		scriptLen, n, err := DecodeVarInt(data[pos:])
		if err != nil {
			return nil, 0, err
		}
		pos += n
		if uint64(pos)+scriptLen > uint64(len(data)) {
			return nil, 0, errTooShort
		}
		out.ScriptPubKey = make([]byte, scriptLen)
		copy(out.ScriptPubKey, data[pos:pos+int(scriptLen)])
		pos += int(scriptLen)
		tx.Outputs[i] = out
	}

	// Witness section — one stack per input, in order.
	for i := range tx.Inputs {
		itemCount, n, err := DecodeVarInt(data[pos:])
		if err != nil {
			return nil, 0, err
		}
		pos += n
		if itemCount == 0 {
			tx.Inputs[i].Witness = nil
			continue
		}
		stack := make([][]byte, itemCount)
		for j := uint64(0); j < itemCount; j++ {
			itemLen, n, err := DecodeVarInt(data[pos:])
			if err != nil {
				return nil, 0, err
			}
			pos += n
			if uint64(pos)+itemLen > uint64(len(data)) {
				return nil, 0, errTooShort
			}
			stack[j] = make([]byte, itemLen)
			copy(stack[j], data[pos:pos+int(itemLen)])
			pos += int(itemLen)
		}
		tx.Inputs[i].Witness = stack
	}

	// LockTime
	if pos+4 > len(data) {
		return nil, 0, errTooShort
	}
	tx.LockTime = binary.LittleEndian.Uint32(data[pos : pos+4])
	pos += 4

	return tx, pos, nil
}

// SerializeTransactions encodes a slice of transactions as:
// varint(count) + each serialized tx.
func SerializeTransactions(txs []*Transaction) []byte {
	var buf bytes.Buffer
	buf.Write(encodeVarInt(uint64(len(txs))))
	for _, tx := range txs {
		buf.Write(tx.Serialize())
	}
	return buf.Bytes()
}

// DeserializeTransactions decodes a slice of transactions from bytes.
func DeserializeTransactions(data []byte) ([]*Transaction, error) {
	if len(data) == 0 {
		return nil, nil
	}
	count, n, err := DecodeVarInt(data)
	if err != nil {
		return nil, err
	}
	pos := n
	txs := make([]*Transaction, 0, count)
	for i := uint64(0); i < count; i++ {
		tx, consumed, err := DeserializeTx(data[pos:])
		if err != nil {
			return nil, err
		}
		txs = append(txs, tx)
		pos += consumed
	}
	return txs, nil
}
