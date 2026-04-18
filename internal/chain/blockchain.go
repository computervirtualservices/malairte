package chain

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/computervirtualservices/malairte/internal/consensus"
	"github.com/computervirtualservices/malairte/internal/primitives"
	"github.com/computervirtualservices/malairte/internal/storage"
)

// Blockchain manages the canonical chain state including the current tip,
// block storage, and UTXO set. All public methods are safe for concurrent use.
type Blockchain struct {
	params  *ChainParams
	db      storage.DB
	utxoSet *UTXOSet
	tip     primitives.BlockHeader // current best tip header
	height  uint64
	mu      sync.RWMutex
}

// NewBlockchain opens (or creates) the blockchain state at the given storage.
// If the database is empty, the genesis block is written automatically.
func NewBlockchain(params *ChainParams, db storage.DB) (*Blockchain, error) {
	utxoSet := NewUTXOSet(db)
	bc := &Blockchain{
		params:  params,
		db:      db,
		utxoSet: utxoSet,
	}

	// Check if we have an existing tip
	tipHash, err := db.Get([]byte(storage.KeyBestTip))
	if err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("read tip hash: %w", err)
		}
		// Fresh database — write the genesis block
		genesis := GenesisBlock(params)
		if err := bc.writeGenesis(genesis); err != nil {
			return nil, fmt.Errorf("write genesis block: %w", err)
		}
		bc.tip = genesis.Header
		bc.height = 0
		// Update params with computed genesis hash
		params.GenesisHash = genesis.Header.Hash()
		return bc, nil
	}

	// Load existing tip
	if len(tipHash) != 32 {
		return nil, fmt.Errorf("invalid tip hash length: %d", len(tipHash))
	}
	var tipHashArr [32]byte
	copy(tipHashArr[:], tipHash)

	header, err := bc.GetBlockHeader(tipHashArr)
	if err != nil {
		return nil, fmt.Errorf("load tip header: %w", err)
	}
	bc.tip = *header
	bc.height = header.Height

	// Update params with genesis hash
	genesisHashRaw, err := db.Get(heightKey(0))
	if err == nil && len(genesisHashRaw) == 32 {
		copy(params.GenesisHash[:], genesisHashRaw)
	}

	return bc, nil
}

// writeGenesis writes the genesis block to storage without validation.
func (bc *Blockchain) writeGenesis(genesis *primitives.Block) error {
	batch := bc.db.NewBatch()

	hash := genesis.Header.Hash()

	// Store block header
	batch.Put(blockKey(hash), genesis.Header.Serialize())

	// Store block transactions
	batch.Put(blockTxsKey(hash), primitives.SerializeTransactions(genesis.Txs))

	// Store height-to-hash mapping
	batch.Put(heightKey(0), hash[:])

	// Set best tip
	batch.Put([]byte(storage.KeyBestTip), hash[:])

	// Index each transaction: txid → block hash
	for _, tx := range genesis.Txs {
		txid := tx.TxID()
		batch.Put(txIndexKey(txid), hash[:])
	}

	// Index P2PKH output addresses: pubKeyHash → txid
	indexBlockAddresses(batch, genesis)

	if err := batch.Write(); err != nil {
		return err
	}

	// Apply genesis UTXOs
	return bc.utxoSet.Apply(genesis)
}

// BestHeight returns the current chain tip height.
func (bc *Blockchain) BestHeight() uint64 {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.height
}

// BestHash returns the hash of the current tip block.
func (bc *Blockchain) BestHash() [32]byte {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.tip.Hash()
}

// BestHeader returns a copy of the current best block header.
func (bc *Blockchain) BestHeader() primitives.BlockHeader {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.tip
}

// GetBlockHeader retrieves a block header by its hash from storage.
func (bc *Blockchain) GetBlockHeader(hash [32]byte) (*primitives.BlockHeader, error) {
	data, err := bc.db.Get(blockKey(hash))
	if err != nil {
		return nil, fmt.Errorf("get block header %x: %w", hash, err)
	}
	return primitives.DeserializeBlockHeader(data)
}

// GetBlock retrieves a full block (header + transactions) by its hash from storage.
func (bc *Blockchain) GetBlock(hash [32]byte) (*primitives.Block, error) {
	headerData, err := bc.db.Get(blockKey(hash))
	if err != nil {
		return nil, fmt.Errorf("get block header %x: %w", hash, err)
	}
	header, err := primitives.DeserializeBlockHeader(headerData)
	if err != nil {
		return nil, fmt.Errorf("deserialize block header: %w", err)
	}

	txData, err := bc.db.Get(blockTxsKey(hash))
	if err != nil {
		return nil, fmt.Errorf("get block txs %x: %w", hash, err)
	}
	txs, err := primitives.DeserializeTransactions(txData)
	if err != nil {
		return nil, fmt.Errorf("deserialize block txs: %w", err)
	}

	return &primitives.Block{Header: *header, Txs: txs}, nil
}

// GetBlockHashAtHeight returns the block hash at the given height.
func (bc *Blockchain) GetBlockHashAtHeight(height uint64) ([32]byte, error) {
	data, err := bc.db.Get(heightKey(height))
	if err != nil {
		return [32]byte{}, fmt.Errorf("get block hash at height %d: %w", height, err)
	}
	if len(data) != 32 {
		return [32]byte{}, fmt.Errorf("invalid hash length %d at height %d", len(data), height)
	}
	var hash [32]byte
	copy(hash[:], data)
	return hash, nil
}

// ProcessBlock validates and adds a new block to the chain.
// Returns nil on success, or an error describing why the block was rejected.
func (bc *Blockchain) ProcessBlock(block *primitives.Block) error {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	hash := block.Header.Hash()

	// Check for duplicate block
	if exists, _ := bc.db.Has(blockKey(hash)); exists {
		return fmt.Errorf("block %x already exists", hash)
	}

	// Only accept blocks that extend the current tip. Without proper reorg
	// logic, accepting same-height forks would corrupt the height→hash index
	// (each thread of a parallel miner produces a competing block at the same
	// height, and overwriting the index breaks all descendants).
	if block.Header.Height > 0 {
		currentTip := bc.tip.Hash()
		if block.Header.PreviousHash != currentTip {
			return fmt.Errorf("block does not extend current tip (parent=%x tip=%x)",
				block.Header.PreviousHash, currentTip)
		}
		if block.Header.Height != bc.height+1 {
			return fmt.Errorf("block height %d is not tip+1 (tip=%d)",
				block.Header.Height, bc.height)
		}
	}

	// Get previous block header for validation
	var prevHeader *primitives.BlockHeader
	if block.Header.Height > 0 {
		var err error
		prevHeader, err = bc.GetBlockHeader(block.Header.PreviousHash)
		if err != nil {
			return fmt.Errorf("get previous header: %w", err)
		}
	}

	// Validate that header.Bits matches the expected difficulty for this height.
	// This must happen before ValidateBlock so that the PoW check uses the
	// correct (network-enforced) target rather than whatever the miner declared.
	expectedBits, err := bc.calcExpectedBits(block.Header.Height, prevHeader)
	if err != nil {
		return fmt.Errorf("calc expected bits: %w", err)
	}
	if block.Header.Bits != expectedBits {
		return fmt.Errorf("block bits %08x does not match expected %08x at height %d",
			block.Header.Bits, expectedBits, block.Header.Height)
	}

	// Full block validation
	if err := ValidateBlock(block, prevHeader, bc.utxoSet, bc.params); err != nil {
		return fmt.Errorf("block validation failed: %w", err)
	}

	// Write block to storage
	batch := bc.db.NewBatch()
	batch.Put(blockKey(hash), block.Header.Serialize())
	batch.Put(blockTxsKey(hash), primitives.SerializeTransactions(block.Txs))
	batch.Put(heightKey(block.Header.Height), hash[:])
	batch.Put([]byte(storage.KeyBestTip), hash[:])

	// Index each transaction: txid → block hash
	for _, tx := range block.Txs {
		txid := tx.TxID()
		batch.Put(txIndexKey(txid), hash[:])
	}

	// Index P2PKH output addresses: pubKeyHash → txid
	indexBlockAddresses(batch, block)

	if err := batch.Write(); err != nil {
		return fmt.Errorf("write block to storage: %w", err)
	}

	// Update UTXO set
	if err := bc.utxoSet.Apply(block); err != nil {
		return fmt.Errorf("apply block to utxo set: %w", err)
	}

	// Update in-memory tip
	bc.tip = block.Header
	bc.height = block.Header.Height

	return nil
}

// CalcNextBits computes the required compact difficulty target for the next block.
// Handles the retarget window logic.
func (bc *Blockchain) CalcNextBits() (uint32, error) {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	currentHeight := bc.height
	currentBits := bc.tip.Bits

	// Check if this is a retarget block
	retargetInterval := bc.params.RetargetInterval
	if (currentHeight+1)%retargetInterval != 0 {
		return currentBits, nil
	}

	// Find the first block of the current retarget window
	windowStartHeight := currentHeight + 1 - retargetInterval
	windowStartHash, err := bc.GetBlockHashAtHeight(windowStartHeight)
	if err != nil {
		return 0, fmt.Errorf("get window start block: %w", err)
	}
	windowStartHeader, err := bc.GetBlockHeader(windowStartHash)
	if err != nil {
		return 0, fmt.Errorf("get window start header: %w", err)
	}

	actualTime := bc.tip.Timestamp - windowStartHeader.Timestamp
	targetTime := bc.params.BlockTime * int64(retargetInterval)

	newBits := consensus.CalcNextRequiredDifficulty(currentBits, actualTime, targetTime)
	return newBits, nil
}

// UTXOSet returns the UTXO set for balance queries.
func (bc *Blockchain) UTXOSet() *UTXOSet {
	return bc.utxoSet
}

// Params returns the chain parameters.
func (bc *Blockchain) Params() *ChainParams {
	return bc.params
}

// GetTransaction retrieves a confirmed transaction by its txid using the txindex.
// Returns ErrNotFound (wrapped) if the transaction is not in any confirmed block.
func (bc *Blockchain) GetTransaction(txid [32]byte) (*primitives.Transaction, error) {
	tx, _, err := bc.GetTransactionWithBlockHash(txid)
	return tx, err
}

// GetTransactionWithBlockHash retrieves a confirmed transaction together with the
// hash of the block it was included in.
func (bc *Blockchain) GetTransactionWithBlockHash(txid [32]byte) (*primitives.Transaction, [32]byte, error) {
	blockHashBytes, err := bc.db.Get(txIndexKey(txid))
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("txindex lookup %x: %w", txid, err)
	}
	if len(blockHashBytes) != 32 {
		return nil, [32]byte{}, fmt.Errorf("corrupt txindex entry for %x: bad block hash length %d", txid, len(blockHashBytes))
	}
	var blockHash [32]byte
	copy(blockHash[:], blockHashBytes)

	txData, err := bc.db.Get(blockTxsKey(blockHash))
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("get block txs for %x: %w", blockHash, err)
	}
	txs, err := primitives.DeserializeTransactions(txData)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("deserialize block txs: %w", err)
	}
	for _, tx := range txs {
		if tx.TxID() == txid {
			return tx, blockHash, nil
		}
	}
	return nil, [32]byte{}, fmt.Errorf("txindex inconsistency: tx %x not found in block %x", txid, blockHash)
}

// calcExpectedBits returns the required compact difficulty target for a block at
// the given height. It must be called with bc.mu held (read or write).
//
//   - height 0 (genesis): returns params.GenesisBits unchanged.
//   - non-retarget height: carries the previous block's Bits unchanged.
//   - retarget height (height % RetargetInterval == 0): recalculates using the
//     elapsed time over the previous RetargetInterval blocks.
func (bc *Blockchain) calcExpectedBits(height uint64, prevHeader *primitives.BlockHeader) (uint32, error) {
	if height == 0 {
		return bc.params.GenesisBits, nil
	}

	if height%bc.params.RetargetInterval != 0 {
		return prevHeader.Bits, nil
	}

	// Retarget: find the header at the start of the window (height - RetargetInterval).
	windowStartHeight := height - bc.params.RetargetInterval
	windowStartHash, err := bc.GetBlockHashAtHeight(windowStartHeight)
	if err != nil {
		return 0, fmt.Errorf("get window-start hash at height %d: %w", windowStartHeight, err)
	}
	windowStartHeader, err := bc.GetBlockHeader(windowStartHash)
	if err != nil {
		return 0, fmt.Errorf("get window-start header: %w", err)
	}

	actualTime := prevHeader.Timestamp - windowStartHeader.Timestamp
	targetTime := int64(bc.params.RetargetInterval) * bc.params.BlockTime
	return consensus.CalcNextRequiredDifficulty(prevHeader.Bits, actualTime, targetTime), nil
}

// blockKey returns the storage key for a block header.
func blockKey(hash [32]byte) []byte {
	key := make([]byte, len(storage.PrefixBlock)+32)
	copy(key, []byte(storage.PrefixBlock))
	copy(key[len(storage.PrefixBlock):], hash[:])
	return key
}

// blockTxsKey returns the storage key for block transactions.
func blockTxsKey(hash [32]byte) []byte {
	key := make([]byte, len(storage.PrefixBlockTxs)+32)
	copy(key, []byte(storage.PrefixBlockTxs))
	copy(key[len(storage.PrefixBlockTxs):], hash[:])
	return key
}

// heightKey returns the storage key for height-to-hash mapping.
func heightKey(height uint64) []byte {
	key := make([]byte, len(storage.PrefixHeight)+8)
	copy(key, []byte(storage.PrefixHeight))
	binary.BigEndian.PutUint64(key[len(storage.PrefixHeight):], height)
	return key
}

// txIndexKey returns the storage key for the transaction index (txid → block hash).
func txIndexKey(txid [32]byte) []byte {
	key := make([]byte, len(storage.PrefixTxIndex)+32)
	copy(key, []byte(storage.PrefixTxIndex))
	copy(key[len(storage.PrefixTxIndex):], txid[:])
	return key
}

// addrIndexPrefix returns the prefix for all address-index entries for a pubkey hash.
// Key layout: "ai/" + 20-byte-pubkeyhash + 8-byte-BE-height + 32-byte-txid
func addrIndexPrefix(pubKeyHash [20]byte) []byte {
	p := len(storage.PrefixAddrIndex)
	prefix := make([]byte, p+20)
	copy(prefix, []byte(storage.PrefixAddrIndex))
	copy(prefix[p:], pubKeyHash[:])
	return prefix
}

// addrIndexKey returns the full address-index key for a given pubkey hash, block height, and txid.
func addrIndexKey(pubKeyHash [20]byte, height uint64, txid [32]byte) []byte {
	p := len(storage.PrefixAddrIndex)
	key := make([]byte, p+20+8+32)
	copy(key, []byte(storage.PrefixAddrIndex))
	copy(key[p:], pubKeyHash[:])
	binary.BigEndian.PutUint64(key[p+20:], height)
	copy(key[p+28:], txid[:])
	return key
}

// indexBlockAddresses writes address-index entries for every P2PKH output in block.
// Called in the same batch as the block write so the index is always consistent.
func indexBlockAddresses(batch storage.Batch, block *primitives.Block) {
	height := block.Header.Height
	for _, tx := range block.Txs {
		txid := tx.TxID()
		for _, out := range tx.Outputs {
			hash, ok := primitives.ExtractP2PKHHash(out.ScriptPubKey)
			if !ok {
				continue
			}
			batch.Put(addrIndexKey(hash, height, txid), []byte{})
		}
	}
}

// AddressTxRecord bundles a confirmed transaction with its containing block's metadata.
type AddressTxRecord struct {
	Tx        *primitives.Transaction
	BlockHash [32]byte
	Height    uint64
	Timestamp int64
}

// GetTransactionsByAddress returns up to limit confirmed transactions whose P2PKH
// outputs paid to pubKeyHash, ordered most-recent-first.
func (bc *Blockchain) GetTransactionsByAddress(pubKeyHash [20]byte, limit int) ([]AddressTxRecord, error) {
	prefix := addrIndexPrefix(pubKeyHash)
	p := len(storage.PrefixAddrIndex)

	type indexEntry struct {
		height uint64
		txid   [32]byte
	}
	var entries []indexEntry

	if err := bc.db.ForEachWithPrefix(prefix, func(key, _ []byte) error {
		// Key: "ai/"(3) + hash(20) + height(8) + txid(32) = 63 bytes minimum
		if len(key) < p+20+8+32 {
			return nil
		}
		height := binary.BigEndian.Uint64(key[p+20 : p+28])
		var txid [32]byte
		copy(txid[:], key[p+28:p+60])
		entries = append(entries, indexEntry{height, txid})
		return nil
	}); err != nil {
		return nil, fmt.Errorf("address index scan: %w", err)
	}

	// Sort descending by height (most recent first).
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].height > entries[j].height
	})
	if limit > 0 && len(entries) > limit {
		entries = entries[:limit]
	}

	result := make([]AddressTxRecord, 0, len(entries))
	for _, e := range entries {
		tx, err := bc.GetTransaction(e.txid)
		if err != nil {
			continue // skip inconsistent entries
		}
		blockHash, err := bc.GetBlockHashAtHeight(e.height)
		if err != nil {
			continue
		}
		header, err := bc.GetBlockHeader(blockHash)
		if err != nil {
			continue
		}
		result = append(result, AddressTxRecord{
			Tx:        tx,
			BlockHash: blockHash,
			Height:    e.height,
			Timestamp: header.Timestamp,
		})
	}
	return result, nil
}
