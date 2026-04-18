package storage

import (
	"errors"
	"fmt"

	badger "github.com/dgraph-io/badger/v4"
)

// ErrNotFound is returned when a key does not exist in the database.
var ErrNotFound = errors.New("key not found")

// BadgerDB implements the DB interface using BadgerDB as the storage backend.
type BadgerDB struct {
	db *badger.DB
}

// OpenBadger opens (or creates) a BadgerDB database at the given path.
// The database is opened with default options suitable for a blockchain node.
func OpenBadger(path string) (*BadgerDB, error) {
	opts := badger.DefaultOptions(path)
	opts.Logger = nil // Suppress default badger logging; use node's logger instead

	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("open badger db at %s: %w", path, err)
	}
	return &BadgerDB{db: db}, nil
}

// Put stores a key-value pair in the database.
func (b *BadgerDB) Put(key, value []byte) error {
	return b.db.Update(func(txn *badger.Txn) error {
		return txn.Set(key, value)
	})
}

// Get retrieves the value for a key. Returns ErrNotFound if the key does not exist.
func (b *BadgerDB) Get(key []byte) ([]byte, error) {
	var val []byte
	err := b.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err != nil {
			if errors.Is(err, badger.ErrKeyNotFound) {
				return ErrNotFound
			}
			return err
		}
		val, err = item.ValueCopy(nil)
		return err
	})
	if err != nil {
		return nil, err
	}
	return val, nil
}

// Delete removes a key from the database. No error if the key does not exist.
func (b *BadgerDB) Delete(key []byte) error {
	return b.db.Update(func(txn *badger.Txn) error {
		err := txn.Delete(key)
		if err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
			return err
		}
		return nil
	})
}

// Has returns true if the key exists in the database.
func (b *BadgerDB) Has(key []byte) (bool, error) {
	var found bool
	err := b.db.View(func(txn *badger.Txn) error {
		_, err := txn.Get(key)
		if err == nil {
			found = true
			return nil
		}
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil
		}
		return err
	})
	return found, err
}

// NewBatch creates a new write batch for atomic operations.
func (b *BadgerDB) NewBatch() Batch {
	return &badgerBatch{
		db:  b.db,
		ops: make([]batchOp, 0, 16),
	}
}

// ForEachWithPrefix iterates over all keys that start with the given prefix,
// calling fn for each key-value pair. Stops if fn returns an error.
func (b *BadgerDB) ForEachWithPrefix(prefix []byte, fn func(key, value []byte) error) error {
	return b.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			key := item.KeyCopy(nil)
			val, err := item.ValueCopy(nil)
			if err != nil {
				return fmt.Errorf("copy value for key %x: %w", key, err)
			}
			if err := fn(key, val); err != nil {
				return err
			}
		}
		return nil
	})
}

// Close closes the BadgerDB database.
func (b *BadgerDB) Close() error {
	return b.db.Close()
}

// batchOp is a single operation in a write batch.
type batchOp struct {
	key    []byte
	value  []byte
	delete bool
}

// badgerBatch implements the Batch interface for BadgerDB.
type badgerBatch struct {
	db  *badger.DB
	ops []batchOp
}

// Put queues a key-value store operation.
func (b *badgerBatch) Put(key, value []byte) {
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	valCopy := make([]byte, len(value))
	copy(valCopy, value)
	b.ops = append(b.ops, batchOp{key: keyCopy, value: valCopy})
}

// Delete queues a key deletion.
func (b *badgerBatch) Delete(key []byte) {
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	b.ops = append(b.ops, batchOp{key: keyCopy, delete: true})
}

// Write atomically commits all queued operations to the database.
func (b *badgerBatch) Write() error {
	return b.db.Update(func(txn *badger.Txn) error {
		for _, op := range b.ops {
			var err error
			if op.delete {
				err = txn.Delete(op.key)
				if errors.Is(err, badger.ErrKeyNotFound) {
					err = nil
				}
			} else {
				err = txn.Set(op.key, op.value)
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
}
