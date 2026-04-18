package chain

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/malairt/malairt/internal/primitives"
	"github.com/malairt/malairt/internal/storage"
)

// UTXO represents an unspent transaction output stored in the UTXO set.
type UTXO struct {
	TxID       [32]byte
	Index      uint32
	Value      int64
	Script     []byte
	Height     uint64
	IsCoinbase bool
}

// Serialize encodes the UTXO to bytes for storage.
func (u *UTXO) Serialize() []byte {
	var buf bytes.Buffer
	buf.Write(u.TxID[:])
	var idx [4]byte
	binary.BigEndian.PutUint32(idx[:], u.Index)
	buf.Write(idx[:])
	var val [8]byte
	binary.LittleEndian.PutUint64(val[:], uint64(u.Value))
	buf.Write(val[:])
	scriptLenBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(scriptLenBytes, uint32(len(u.Script)))
	buf.Write(scriptLenBytes)
	buf.Write(u.Script)
	var ht [8]byte
	binary.LittleEndian.PutUint64(ht[:], u.Height)
	buf.Write(ht[:])
	if u.IsCoinbase {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	return buf.Bytes()
}

// DeserializeUTXO decodes a UTXO from storage bytes.
func DeserializeUTXO(data []byte) (*UTXO, error) {
	if len(data) < 32+4+8+4 {
		return nil, fmt.Errorf("utxo data too short: %d bytes", len(data))
	}
	u := &UTXO{}
	pos := 0
	copy(u.TxID[:], data[pos:pos+32])
	pos += 32
	u.Index = binary.BigEndian.Uint32(data[pos : pos+4])
	pos += 4
	u.Value = int64(binary.LittleEndian.Uint64(data[pos : pos+8]))
	pos += 8
	scriptLen := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
	pos += 4
	if pos+scriptLen > len(data) {
		return nil, fmt.Errorf("utxo script length %d exceeds data", scriptLen)
	}
	u.Script = make([]byte, scriptLen)
	copy(u.Script, data[pos:pos+scriptLen])
	pos += scriptLen
	if pos+8 > len(data) {
		return nil, fmt.Errorf("utxo data too short for height")
	}
	u.Height = binary.LittleEndian.Uint64(data[pos : pos+8])
	pos += 8
	if pos < len(data) {
		u.IsCoinbase = data[pos] == 1
	}
	return u, nil
}

// UTXOSet is the set of all unspent transaction outputs, backed by persistent storage.
type UTXOSet struct {
	db storage.DB
}

// NewUTXOSet creates a UTXOSet backed by the given storage.
func NewUTXOSet(db storage.DB) *UTXOSet {
	return &UTXOSet{db: db}
}

// utxoKey constructs the storage key for a UTXO identified by outpoint.
// Format: "u/" + 32-byte-txid + "/" + 4-byte-BE-index
func utxoKey(op primitives.OutPoint) []byte {
	key := make([]byte, len(storage.PrefixUTXO)+32+1+4)
	pos := 0
	copy(key[pos:], []byte(storage.PrefixUTXO))
	pos += len(storage.PrefixUTXO)
	copy(key[pos:], op.TxID[:])
	pos += 32
	key[pos] = '/'
	pos++
	binary.BigEndian.PutUint32(key[pos:], op.Index)
	return key
}

// Get retrieves a UTXO by its outpoint. Returns (utxo, true) if found, (nil, false) if not.
func (u *UTXOSet) Get(op primitives.OutPoint) (*UTXO, bool) {
	key := utxoKey(op)
	data, err := u.db.Get(key)
	if err != nil {
		return nil, false
	}
	utxo, err := DeserializeUTXO(data)
	if err != nil {
		return nil, false
	}
	return utxo, true
}

// spentUTXO pairs an outpoint with the UTXO that was consumed at that outpoint.
// This is the unit of undo data written alongside each applied block.
type spentUTXO struct {
	outPoint primitives.OutPoint
	utxo     UTXO
}

// serializeUndoData encodes a slice of spentUTXO records as:
// varint(count) + [36-byte-outpoint + 4-byte-LE-utxo-len + utxo-bytes]*
func serializeUndoData(spent []spentUTXO) []byte {
	buf := primitives.EncodeVarIntPub(uint64(len(spent)))
	for _, s := range spent {
		// outpoint: TxID (32 bytes) + Index (4 bytes BE)
		op := make([]byte, 36)
		copy(op[:32], s.outPoint.TxID[:])
		binary.BigEndian.PutUint32(op[32:], s.outPoint.Index)
		buf = append(buf, op...)
		// utxo
		utxoBytes := s.utxo.Serialize()
		lenBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(lenBytes, uint32(len(utxoBytes)))
		buf = append(buf, lenBytes...)
		buf = append(buf, utxoBytes...)
	}
	return buf
}

// deserializeUndoData decodes a byte slice produced by serializeUndoData.
func deserializeUndoData(data []byte) ([]spentUTXO, error) {
	count, n, err := primitives.DecodeVarInt(data)
	if err != nil {
		return nil, fmt.Errorf("decode undo count: %w", err)
	}
	pos := n
	spent := make([]spentUTXO, 0, count)
	for i := uint64(0); i < count; i++ {
		if pos+36 > len(data) {
			return nil, fmt.Errorf("undo record %d: too short for outpoint", i)
		}
		var s spentUTXO
		copy(s.outPoint.TxID[:], data[pos:pos+32])
		s.outPoint.Index = binary.BigEndian.Uint32(data[pos+32 : pos+36])
		pos += 36

		if pos+4 > len(data) {
			return nil, fmt.Errorf("undo record %d: too short for utxo length", i)
		}
		utxoLen := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
		pos += 4

		if pos+utxoLen > len(data) {
			return nil, fmt.Errorf("undo record %d: utxo data overflows buffer", i)
		}
		utxo, err := DeserializeUTXO(data[pos : pos+utxoLen])
		if err != nil {
			return nil, fmt.Errorf("undo record %d: %w", i, err)
		}
		s.utxo = *utxo
		pos += utxoLen
		spent = append(spent, s)
	}
	return spent, nil
}

// undoKey returns the storage key for block undo data.
func undoKey(blockHash [32]byte) []byte {
	key := make([]byte, len(storage.PrefixBlockUndo)+32)
	copy(key, []byte(storage.PrefixBlockUndo))
	copy(key[len(storage.PrefixBlockUndo):], blockHash[:])
	return key
}

// Apply processes all transactions in a block, adding new UTXOs and removing spent ones.
// It also records undo data (the consumed UTXOs) so that the block can be reverted later.
// This is called when a block is added to the chain.
func (u *UTXOSet) Apply(block *primitives.Block) error {
	blockHash := block.Header.Hash()
	batch := u.db.NewBatch()
	var spent []spentUTXO

	for _, tx := range block.Txs {
		txID := tx.TxID()
		isCoinbase := tx.IsCoinbase()

		// Remove spent inputs and record undo data (skip coinbase inputs)
		if !isCoinbase {
			for _, in := range tx.Inputs {
				key := utxoKey(in.PreviousOutput)
				// Load the UTXO before deleting so we can store it as undo data
				data, err := u.db.Get(key)
				if err == nil {
					if existing, err := DeserializeUTXO(data); err == nil {
						spent = append(spent, spentUTXO{outPoint: in.PreviousOutput, utxo: *existing})
					}
				}
				batch.Delete(key)
			}
		}

		// Add new outputs as UTXOs
		for i, out := range tx.Outputs {
			op := primitives.OutPoint{TxID: txID, Index: uint32(i)}
			utxo := &UTXO{
				TxID:       txID,
				Index:      uint32(i),
				Value:      out.Value,
				Script:     out.ScriptPubKey,
				Height:     block.Header.Height,
				IsCoinbase: isCoinbase,
			}
			batch.Put(utxoKey(op), utxo.Serialize())
		}
	}

	// Persist undo data alongside the block
	batch.Put(undoKey(blockHash), serializeUndoData(spent))

	return batch.Write()
}

// Revert undoes the Apply operation for a block using the stored undo data.
// Called during a chain reorganization when the block is disconnected from the tip.
func (u *UTXOSet) Revert(block *primitives.Block) error {
	blockHash := block.Header.Hash()

	// Load undo data
	undoBytes, err := u.db.Get(undoKey(blockHash))
	if err != nil {
		return fmt.Errorf("load undo data for block %x: %w", blockHash, err)
	}
	spent, err := deserializeUndoData(undoBytes)
	if err != nil {
		return fmt.Errorf("decode undo data for block %x: %w", blockHash, err)
	}

	batch := u.db.NewBatch()

	// Remove all UTXOs that were created by this block
	for _, tx := range block.Txs {
		txID := tx.TxID()
		for i := range tx.Outputs {
			op := primitives.OutPoint{TxID: txID, Index: uint32(i)}
			batch.Delete(utxoKey(op))
		}
	}

	// Restore all UTXOs that were consumed by this block
	for _, s := range spent {
		batch.Put(utxoKey(s.outPoint), s.utxo.Serialize())
	}

	// Delete the undo record itself
	batch.Delete(undoKey(blockHash))

	return batch.Write()
}

// Balance returns the total unspent balance in atoms for a given P2PKH pubkey hash.
// It scans all UTXOs — this is O(n) in the UTXO set size.
func (u *UTXOSet) Balance(pubKeyHash [20]byte) int64 {
	targetScript := primitives.P2PKHScript(pubKeyHash)
	var total int64

	_ = u.db.ForEachWithPrefix([]byte(storage.PrefixUTXO), func(key, value []byte) error {
		utxo, err := DeserializeUTXO(value)
		if err != nil {
			return nil // skip malformed entries
		}
		if len(utxo.Script) == len(targetScript) {
			match := true
			for i := range targetScript {
				if utxo.Script[i] != targetScript[i] {
					match = false
					break
				}
			}
			if match {
				total += utxo.Value
			}
		}
		return nil
	})

	return total
}

// GetUTXOsByAddress returns all unspent outputs that pay to the given P2PKH pubkey hash.
// It scans all UTXOs — this is O(n) in the UTXO set size.
func (u *UTXOSet) GetUTXOsByAddress(pubKeyHash [20]byte) ([]*UTXO, error) {
	targetScript := primitives.P2PKHScript(pubKeyHash)
	var results []*UTXO

	err := u.db.ForEachWithPrefix([]byte(storage.PrefixUTXO), func(key, value []byte) error {
		utxo, err := DeserializeUTXO(value)
		if err != nil {
			return nil // skip malformed entries
		}
		if len(utxo.Script) == len(targetScript) {
			match := true
			for i := range targetScript {
				if utxo.Script[i] != targetScript[i] {
					match = false
					break
				}
			}
			if match {
				results = append(results, utxo)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return results, nil
}
