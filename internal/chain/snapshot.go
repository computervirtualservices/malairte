package chain

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/computervirtualservices/malairte/internal/primitives"
	"github.com/computervirtualservices/malairte/internal/storage"
)

// AssumeUTXO — snapshot-based fast sync.
//
// A snapshot is the full UTXO set serialized in a canonical order. New nodes
// can bootstrap from a trusted snapshot instead of replaying every historical
// block: they load the snapshot, verify its hash matches a value compiled into
// ChainParams.AssumeUTXOHash (protected by the same release signing as the
// binary), and immediately start validating new blocks on top.
//
// Historical blocks can still be downloaded and replayed in the background to
// upgrade from "trusted snapshot" to "fully-validated chain" — the snapshot
// is an optimisation, not a weakening of the consensus model.
//
// SNAPSHOT FORMAT (deterministic, little-endian unless noted):
//   magic      [4] bytes — "MLSN" (Malairt Snapshot)
//   version    uint32    — format version, starts at 1
//   height     uint64    — the block height the snapshot commits to
//   blockHash  [32] bytes — the block hash at that height
//   count      uint64    — number of UTXO records
//   records    []         — count entries, each = (varint(len) + utxo.Serialize())
// Records are sorted by (TxID, Index) to make hashing deterministic across
// implementations.

const (
	snapshotMagic   = "MLSN"
	snapshotVersion = uint32(1)
)

// Snapshot is the in-memory representation of a UTXO snapshot.
type Snapshot struct {
	Height    uint64
	BlockHash [32]byte
	UTXOs     []*UTXO
}

// Build constructs a Snapshot by iterating the current UTXO set. The returned
// snapshot contains the caller's view of the chain at the moment Build was
// called — the tip height and hash are captured up front; concurrent Apply
// calls during iteration are not safe.
func BuildSnapshot(bc *Blockchain) (*Snapshot, error) {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	tip := bc.tip
	height := bc.height
	var utxos []*UTXO
	err := bc.db.ForEachWithPrefix([]byte(storage.PrefixUTXO), func(_, value []byte) error {
		u, err := DeserializeUTXO(value)
		if err != nil {
			return fmt.Errorf("snapshot: deserialize utxo: %w", err)
		}
		utxos = append(utxos, u)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(utxos, func(i, j int) bool {
		c := bytes.Compare(utxos[i].TxID[:], utxos[j].TxID[:])
		if c != 0 {
			return c < 0
		}
		return utxos[i].Index < utxos[j].Index
	})
	return &Snapshot{
		Height:    height,
		BlockHash: tip.Hash(),
		UTXOs:     utxos,
	}, nil
}

// Serialize encodes the snapshot in canonical form. Two calls with the same
// UTXO set produce byte-identical output.
func (s *Snapshot) Serialize() []byte {
	var buf bytes.Buffer
	buf.WriteString(snapshotMagic)
	var tmp [8]byte
	binary.LittleEndian.PutUint32(tmp[:4], snapshotVersion)
	buf.Write(tmp[:4])
	binary.LittleEndian.PutUint64(tmp[:], s.Height)
	buf.Write(tmp[:])
	buf.Write(s.BlockHash[:])
	binary.LittleEndian.PutUint64(tmp[:], uint64(len(s.UTXOs)))
	buf.Write(tmp[:])
	for _, u := range s.UTXOs {
		body := u.Serialize()
		buf.Write(primitives.EncodeVarIntPub(uint64(len(body))))
		buf.Write(body)
	}
	return buf.Bytes()
}

// Hash returns SHA256 over the serialized snapshot — the value a
// compiled-in AssumeUTXOHash must match for loadsnapshot to accept the
// snapshot as authoritative.
func (s *Snapshot) Hash() [32]byte {
	return sha256.Sum256(s.Serialize())
}

// DeserializeSnapshot decodes the snapshot wire format. Every record is
// independently validated and reconstructed; a malformed tail returns an
// error rather than partial state.
func DeserializeSnapshot(data []byte) (*Snapshot, error) {
	if len(data) < 4+4+8+32+8 {
		return nil, fmt.Errorf("snapshot: header too short (%d bytes)", len(data))
	}
	if string(data[:4]) != snapshotMagic {
		return nil, fmt.Errorf("snapshot: bad magic %x", data[:4])
	}
	pos := 4
	version := binary.LittleEndian.Uint32(data[pos : pos+4])
	pos += 4
	if version != snapshotVersion {
		return nil, fmt.Errorf("snapshot: unsupported version %d", version)
	}
	snap := &Snapshot{}
	snap.Height = binary.LittleEndian.Uint64(data[pos : pos+8])
	pos += 8
	copy(snap.BlockHash[:], data[pos:pos+32])
	pos += 32
	count := binary.LittleEndian.Uint64(data[pos : pos+8])
	pos += 8
	snap.UTXOs = make([]*UTXO, 0, count)

	for i := uint64(0); i < count; i++ {
		l, consumed, err := primitives.DecodeVarInt(data[pos:])
		if err != nil {
			return nil, fmt.Errorf("snapshot: record %d length: %w", i, err)
		}
		pos += consumed
		if uint64(pos)+l > uint64(len(data)) {
			return nil, fmt.Errorf("snapshot: record %d truncated", i)
		}
		u, err := DeserializeUTXO(data[pos : pos+int(l)])
		if err != nil {
			return nil, fmt.Errorf("snapshot: record %d: %w", i, err)
		}
		snap.UTXOs = append(snap.UTXOs, u)
		pos += int(l)
	}
	if pos != len(data) {
		return nil, fmt.Errorf("snapshot: %d trailing bytes", len(data)-pos)
	}
	return snap, nil
}

// LoadSnapshot writes every UTXO in snap into the given DB using the same
// key format the rest of the codebase uses (via utxoKey). Pre-existing
// UTXO entries are not cleared — callers should only invoke this on a fresh
// DB. Returns the number of UTXOs written.
func LoadSnapshot(db storage.DB, snap *Snapshot) (int, error) {
	if snap == nil {
		return 0, fmt.Errorf("snapshot: nil")
	}
	batch := db.NewBatch()
	for _, u := range snap.UTXOs {
		op := primitives.OutPoint{TxID: u.TxID, Index: u.Index}
		batch.Put(utxoKey(op), u.Serialize())
	}
	if err := batch.Write(); err != nil {
		return 0, err
	}
	return len(snap.UTXOs), nil
}
