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
type TxInput struct {
	PreviousOutput OutPoint
	ScriptSig      []byte
	Sequence       uint32
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

// TxID returns Hash256(tx.Serialize()) — the transaction ID.
// Coinbase inputs have PreviousOutput = OutPoint{TxID: [32]byte{}, Index: 0xFFFFFFFF}.
func (tx *Transaction) TxID() [32]byte {
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

// Serialize encodes the full transaction to bytes using Bitcoin-style serialization.
// Format: version(4) + varint(inputCount) + inputs + varint(outputCount) + outputs + locktime(4).
func (tx *Transaction) Serialize() []byte {
	var buf bytes.Buffer

	// Version (4 bytes LE)
	var versionBytes [4]byte
	binary.LittleEndian.PutUint32(versionBytes[:], tx.Version)
	buf.Write(versionBytes[:])

	// Input count (varint)
	buf.Write(encodeVarInt(uint64(len(tx.Inputs))))

	// Each input
	for _, in := range tx.Inputs {
		// Previous output TxID (32 bytes)
		buf.Write(in.PreviousOutput.TxID[:])
		// Previous output index (4 bytes LE)
		var idxBytes [4]byte
		binary.LittleEndian.PutUint32(idxBytes[:], in.PreviousOutput.Index)
		buf.Write(idxBytes[:])
		// ScriptSig length (varint) + ScriptSig
		buf.Write(encodeVarInt(uint64(len(in.ScriptSig))))
		buf.Write(in.ScriptSig)
		// Sequence (4 bytes LE)
		var seqBytes [4]byte
		binary.LittleEndian.PutUint32(seqBytes[:], in.Sequence)
		buf.Write(seqBytes[:])
	}

	// Output count (varint)
	buf.Write(encodeVarInt(uint64(len(tx.Outputs))))

	// Each output
	for _, out := range tx.Outputs {
		// Value (8 bytes LE)
		var valBytes [8]byte
		binary.LittleEndian.PutUint64(valBytes[:], uint64(out.Value))
		buf.Write(valBytes[:])
		// ScriptPubKey length (varint) + ScriptPubKey
		buf.Write(encodeVarInt(uint64(len(out.ScriptPubKey))))
		buf.Write(out.ScriptPubKey)
	}

	// LockTime (4 bytes LE)
	var ltBytes [4]byte
	binary.LittleEndian.PutUint32(ltBytes[:], tx.LockTime)
	buf.Write(ltBytes[:])

	return buf.Bytes()
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

// DeserializeTx deserializes a transaction from bytes.
// Returns the transaction and the number of bytes consumed.
func DeserializeTx(data []byte) (*Transaction, int, error) {
	if len(data) < 4 {
		return nil, 0, errTooShort
	}
	pos := 0
	tx := &Transaction{}

	// Version
	tx.Version = binary.LittleEndian.Uint32(data[pos : pos+4])
	pos += 4

	// Input count
	inputCount, n, err := DecodeVarInt(data[pos:])
	if err != nil {
		return nil, 0, err
	}
	pos += n

	// Inputs
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
