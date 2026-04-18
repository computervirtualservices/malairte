// Package storage provides the storage abstraction layer for the Malairt blockchain.
package storage

// DB is the storage abstraction for all chain data.
// Implementations must be safe for concurrent use.
type DB interface {
	// Put stores a key-value pair.
	Put(key, value []byte) error
	// Get retrieves the value for a key. Returns ErrNotFound if the key does not exist.
	Get(key []byte) ([]byte, error)
	// Delete removes a key-value pair. No error if key does not exist.
	Delete(key []byte) error
	// Has returns true if the key exists.
	Has(key []byte) (bool, error)
	// NewBatch creates a new write batch for atomic multi-key operations.
	NewBatch() Batch
	// ForEachWithPrefix iterates over all keys with the given prefix,
	// calling fn for each key-value pair. Iteration stops if fn returns an error.
	ForEachWithPrefix(prefix []byte, fn func(key, value []byte) error) error
	// Close closes the database and releases all resources.
	Close() error
}

// Batch is an atomic write batch.
// All operations are buffered until Write() is called.
type Batch interface {
	// Put queues a key-value store operation.
	Put(key, value []byte)
	// Delete queues a key deletion.
	Delete(key []byte)
	// Write atomically commits all queued operations.
	Write() error
}

// Storage key prefix conventions:
//
//	Block header by hash:   "b/"  + 32-byte-hash  → serialized BlockHeader (96 bytes)
//	Block txs by hash:      "bx/" + 32-byte-hash  → serialized []Transaction
//	Height to hash:         "h/"  + 8-byte-BE-height → 32-byte hash
//	Best tip:               "tip"                  → 32-byte hash
//	UTXO:                   "u/"  + 32-byte-txid + "/" + 4-byte-BE-index → serialized UTXO
//	Block undo data:        "bu/" + 32-byte-hash  → serialized []SpentUTXO (for reorg revert)
//	Transaction index:      "tx/" + 32-byte-txid  → 32-byte block hash
//	Address tx index:       "ai/" + 20-byte-pubkeyhash + 8-byte-BE-height + 32-byte-txid → []byte{}
const (
	PrefixBlock     = "b/"
	PrefixBlockTxs  = "bx/"
	PrefixHeight    = "h/"
	KeyBestTip      = "tip"
	PrefixUTXO      = "u/"
	PrefixBlockUndo = "bu/"
	PrefixTxIndex   = "tx/"
	PrefixAddrIndex = "ai/"
)
