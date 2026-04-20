package chain

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/computervirtualservices/malairte/internal/consensus"
	"github.com/computervirtualservices/malairte/internal/crypto"
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

	// Store compact block filter (output-only for genesis — no prevouts)
	// and its BIP-157 filter header commitment (prev header = zeros).
	genesisFilter := BuildBlockFilter(genesis, nil)
	batch.Put(cfilterKey(hash), genesisFilter)
	genesisCFHeader := FilterHeader(FilterHash(genesisFilter), [32]byte{})
	batch.Put(cfheaderKey(hash), genesisCFHeader[:])

	// Store height-to-hash mapping
	batch.Put(heightKey(0), hash[:])

	// Seed cumulative chainwork at genesis so reorg comparisons have a
	// consistent basis (otherwise computeBranchChainWork walks to genesis
	// and adds its work, while the happy-path's parent-lookup at genesis
	// returns 0 — the mismatch would flag equal-work forks as wins).
	putChainWork(batch, hash, compactWork(genesis.Header.Bits))

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

	// Classify the incoming block relative to our current tip:
	//   - block extends tip      → normal forward progression
	//   - block's parent == tip's parent → sibling of the tip; could trigger
	//     a single-block reorg if it carries more work
	//   - deeper fork            → currently rejected. Multi-block reorgs are
	//     a planned follow-up; nothing prevents them from being added by
	//     tracking chainwork per branch tip.
	if block.Header.Height > 0 {
		currentTip := bc.tip.Hash()
		if block.Header.PreviousHash != currentTip {
			// Sibling of the current tip → single-depth reorg path.
			if block.Header.PreviousHash == bc.tip.PreviousHash && block.Header.Height == bc.height {
				return bc.handleSiblingBlock(block)
			}
			// Deeper fork: parent is a known block but not the tip or the
			// tip's parent. Handle via the multi-depth path if we can find
			// the parent in storage; otherwise reject.
			if _, err := bc.GetBlockHeader(block.Header.PreviousHash); err == nil {
				return bc.handleDeeperFork(block)
			}
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
	expectedBits, err := bc.calcExpectedBits(block.Header.Height, prevHeader, block.Header.Timestamp)
	if err != nil {
		return fmt.Errorf("calc expected bits: %w", err)
	}
	if block.Header.Bits != expectedBits {
		return fmt.Errorf("block bits %08x does not match expected %08x at height %d",
			block.Header.Bits, expectedBits, block.Header.Height)
	}

	// Enforce median-time-past: the block's timestamp must be strictly greater
	// than the median of the previous up-to-11 block timestamps. Replaces the
	// naive `> prev.Timestamp` check (still performed by ValidateBlockHeader)
	// with the Bitcoin standard — tolerates small clock skew across miners but
	// still prevents time-warp attacks that would bias the LWMA window.
	if block.Header.Height > 0 {
		mtpWindow, err := bc.fetchPrevHeaderWindow(prevHeader, 11)
		if err != nil {
			return fmt.Errorf("fetch mtp window: %w", err)
		}
		if mtp := consensus.CalcMedianTimePast(mtpWindow); block.Header.Timestamp <= mtp {
			return fmt.Errorf("block timestamp %d not greater than median-time-past %d",
				block.Header.Timestamp, mtp)
		}
	}

	// Full block validation
	if err := ValidateBlock(block, prevHeader, bc.utxoSet, bc.params); err != nil {
		return fmt.Errorf("block validation failed: %w", err)
	}

	// Resolve spent-input scripts BEFORE UTXOSet.Apply consumes them. These
	// go into the compact block filter so light clients can detect spends
	// of their addresses without downloading the full block.
	var spentScripts [][]byte
	for _, tx := range block.Txs {
		if tx.IsCoinbase() {
			continue
		}
		for _, in := range tx.Inputs {
			if u, ok := bc.utxoSet.Get(in.PreviousOutput); ok {
				spentScripts = append(spentScripts, u.Script)
			}
		}
	}
	cfilter := BuildBlockFilter(block, spentScripts)
	// Build the BIP-157 filter header, chained from the previous block's.
	var prevCFHeader [32]byte
	if block.Header.Height > 0 {
		if h, err := bc.db.Get(cfheaderKey(block.Header.PreviousHash)); err == nil && len(h) == 32 {
			copy(prevCFHeader[:], h)
		}
	}
	cfheader := FilterHeader(FilterHash(cfilter), prevCFHeader)

	// Record cumulative chainwork so future reorg comparisons are O(1).
	parentWork := bc.getChainWork(block.Header.PreviousHash)
	newChainWork := new(big.Int).Add(parentWork, compactWork(block.Header.Bits))

	// Write block to storage
	batch := bc.db.NewBatch()
	batch.Put(blockKey(hash), block.Header.Serialize())
	batch.Put(blockTxsKey(hash), primitives.SerializeTransactions(block.Txs))
	batch.Put(heightKey(block.Header.Height), hash[:])
	batch.Put(cfilterKey(hash), cfilter)
	batch.Put(cfheaderKey(hash), cfheader[:])
	putChainWork(batch, hash, newChainWork)
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

// CalcNextBits computes the required compact difficulty target for the next
// block to be mined on top of the current tip, using LWMA over the last
// consensus.LWMAWindow blocks. During the initial ramp-up (tip height <
// LWMAWindow) it returns the pow-limit target so blocks can be found at any
// difficulty up to that bound.
//
// If params.AllowMinDifficultyBlocks is set and wall-clock time is more than
// 2 * BlockTime past the tip, returns PowLimitBits so a miner can find a
// block quickly after a network stall (Bitcoin testnet rule).
func (bc *Blockchain) CalcNextBits() (uint32, error) {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	if bc.params.AllowMinDifficultyBlocks {
		if time.Now().Unix() > bc.tip.Timestamp+2*bc.params.BlockTime {
			return bc.params.PowLimitBits, nil
		}
	}

	if bc.height < consensus.LWMAWindow {
		return bc.params.PowLimitBits, nil
	}

	window, err := bc.fetchPrevHeaderWindow(&bc.tip, consensus.LWMAWindow+1)
	if err != nil {
		return 0, fmt.Errorf("fetch lwma window: %w", err)
	}
	return consensus.NextRequiredBitsLWMA(window, bc.params.BlockTime, bc.params.PowLimitBits), nil
}

// UTXOSet returns the UTXO set for balance queries.
func (bc *Blockchain) UTXOSet() *UTXOSet {
	return bc.utxoSet
}

// DB returns the underlying key-value store. Exposed for administrative RPCs
// like loadsnapshot that need direct write access outside the normal block
// validation path.
func (bc *Blockchain) DB() storage.DB {
	return bc.db
}

// handleDeeperFork processes a block whose parent is a known block other
// than the current tip or the tip's parent — meaning the sender is
// building on an older alternate chain. We validate the block's header,
// persist it alongside the main chain, then compare cumulative chainwork.
// If the new branch tip exceeds the current tip, reorganise via
// reorgToSideBranch.
//
// Caller holds bc.mu in write mode.
func (bc *Blockchain) handleDeeperFork(block *primitives.Block) error {
	hash := block.Header.Hash()
	// Header-level sanity: PoW must meet the block's declared target.
	if !consensus.HashMeetsDifficulty(block.Header.Hash(), block.Header.Bits) {
		return fmt.Errorf("deeper fork: PoW check failed for %x", hash)
	}
	// Persist the block body; we may need it during a reorg.
	if err := bc.storeSideChainBlockLocked(block); err != nil {
		return fmt.Errorf("deeper fork: store block: %w", err)
	}

	// Compute the new branch's cumulative chainwork and compare.
	newWork, err := bc.computeBranchChainWork(hash)
	if err != nil {
		return fmt.Errorf("deeper fork: chainwork: %w", err)
	}
	// Cache the new work under this hash so a follow-up extension can find
	// it without re-walking.
	batch := bc.db.NewBatch()
	putChainWork(batch, hash, newWork)
	if err := batch.Write(); err != nil {
		return fmt.Errorf("deeper fork: persist chainwork: %w", err)
	}

	tipWork := bc.getChainWork(bc.tip.Hash())
	if tipWork.Sign() == 0 {
		// Main tip has no cached work yet (early-deployment race). Compute
		// and cache so future comparisons are cheap.
		tw, werr := bc.computeBranchChainWork(bc.tip.Hash())
		if werr == nil {
			b := bc.db.NewBatch()
			putChainWork(b, bc.tip.Hash(), tw)
			_ = b.Write()
			tipWork = tw
		}
	}

	if newWork.Cmp(tipWork) <= 0 {
		// Not enough work to win — chain stored for future but not canonical.
		return fmt.Errorf("deeper fork stored: branch work %s ≤ main work %s",
			newWork.Text(10), tipWork.Text(10))
	}
	// New branch wins — reorganise.
	return bc.reorgToSideBranch(hash)
}

// handleSiblingBlock processes a block that is a direct sibling of the
// current tip — same parent, same height. Such a block represents a
// one-block competing fork. We apply the "more work wins" rule: if the
// challenger's compact-bits target implies a harder PoW than the current
// tip, we reorganise by disconnecting the tip and connecting the challenger.
//
// Equal-work or lower-work sibling: store the block header so we don't
// request it again, but do not change the canonical chain. This matches
// Bitcoin Core's first-seen rule.
//
// Caller holds bc.mu in write mode (this is called directly from
// ProcessBlock before it has released the lock).
func (bc *Blockchain) handleSiblingBlock(challenger *primitives.Block) error {
	challengerHash := challenger.Header.Hash()
	tipHash := bc.tip.Hash()

	// Quick-path: record the challenger's header + body so if it later
	// builds a longer chain we have the data. We keep only what's safe to
	// store without affecting canonical state.
	if err := bc.storeSideChainBlockLocked(challenger); err != nil {
		return fmt.Errorf("store side-chain block: %w", err)
	}

	challengerWork := compactWork(challenger.Header.Bits)
	tipWork := compactWork(bc.tip.Bits)
	if challengerWork.Cmp(tipWork) <= 0 {
		// Challenger doesn't exceed current tip — keep canonical chain,
		// log the fork for operator visibility.
		return fmt.Errorf("sibling fork ignored: challenger %x work %s ≤ tip %x work %s",
			challengerHash, challengerWork.Text(10), tipHash, tipWork.Text(10))
	}

	// Challenger wins — reorganise. Load the current tip's full block so we
	// can revert its effects on the UTXO set.
	tipBlock, err := bc.getBlockLocked(tipHash)
	if err != nil {
		return fmt.Errorf("reorg: load current tip: %w", err)
	}
	// Disconnect the current tip.
	if err := bc.utxoSet.Revert(tipBlock); err != nil {
		return fmt.Errorf("reorg: revert current tip: %w", err)
	}
	// The height → hash index now points at the OLD tip. It will be
	// overwritten when we connect the challenger below. The block body and
	// header stay in storage under their own hash keys — reorgs in the
	// other direction (back to the old tip) could reuse them.
	// Roll bc.tip back to the parent for the duration of re-validation.
	parentHdr, err := bc.GetBlockHeader(bc.tip.PreviousHash)
	if err != nil {
		return fmt.Errorf("reorg: load parent header: %w", err)
	}
	bc.tip = *parentHdr
	bc.height = parentHdr.Height

	// Now connect the challenger as the new tip using the normal validation
	// path. The sibling-detection branch in ProcessBlock already ran, so we
	// re-enter via an internal applyLocked that assumes tip is set correctly.
	if err := bc.applyLocked(challenger); err != nil {
		// Reorg failed — rollback. Re-apply the original tip to restore
		// the chain as it was.
		if applyErr := bc.applyLocked(tipBlock); applyErr != nil {
			// This is genuinely bad — we've partially reverted and can't
			// recover. Return both errors so an operator sees the full
			// story. bc.height / bc.tip are wrong and the DB may need
			// manual rebuilding from a snapshot.
			return fmt.Errorf("reorg failed AND rollback failed: challenger err=%v rollback err=%v",
				err, applyErr)
		}
		return fmt.Errorf("reorg: challenger rejected, original tip restored: %w", err)
	}

	return nil
}

// storeSideChainBlockLocked persists an alternate-chain block's header + txs
// so future reorg logic can fetch them. No canonical-chain side effects.
func (bc *Blockchain) storeSideChainBlockLocked(block *primitives.Block) error {
	hash := block.Header.Hash()
	batch := bc.db.NewBatch()
	batch.Put(blockKey(hash), block.Header.Serialize())
	batch.Put(blockTxsKey(hash), primitives.SerializeTransactions(block.Txs))
	return batch.Write()
}

// getBlockLocked is GetBlock without re-acquiring the mutex. Caller holds it.
func (bc *Blockchain) getBlockLocked(hash [32]byte) (*primitives.Block, error) {
	headerData, err := bc.db.Get(blockKey(hash))
	if err != nil {
		return nil, err
	}
	header, err := primitives.DeserializeBlockHeader(headerData)
	if err != nil {
		return nil, err
	}
	txData, err := bc.db.Get(blockTxsKey(hash))
	if err != nil {
		return nil, err
	}
	txs, err := primitives.DeserializeTransactions(txData)
	if err != nil {
		return nil, err
	}
	return &primitives.Block{Header: *header, Txs: txs}, nil
}

// applyLocked runs the full validation and apply pipeline for a block
// assuming bc.tip and bc.height point at its parent. Used by the reorg
// path when rebuilding a chain from scratch.
func (bc *Blockchain) applyLocked(block *primitives.Block) error {
	hash := block.Header.Hash()

	prevHeader, err := bc.GetBlockHeader(block.Header.PreviousHash)
	if err != nil {
		return fmt.Errorf("get previous header: %w", err)
	}
	expectedBits, err := bc.calcExpectedBits(block.Header.Height, prevHeader, block.Header.Timestamp)
	if err != nil {
		return fmt.Errorf("calc expected bits: %w", err)
	}
	if block.Header.Bits != expectedBits {
		return fmt.Errorf("block bits %08x does not match expected %08x", block.Header.Bits, expectedBits)
	}
	if block.Header.Height > 0 {
		mtpWindow, err := bc.fetchPrevHeaderWindow(prevHeader, 11)
		if err != nil {
			return err
		}
		if mtp := consensus.CalcMedianTimePast(mtpWindow); block.Header.Timestamp <= mtp {
			return fmt.Errorf("block timestamp %d not greater than mtp %d", block.Header.Timestamp, mtp)
		}
	}
	var spentScripts [][]byte
	for _, tx := range block.Txs {
		if tx.IsCoinbase() {
			continue
		}
		for _, in := range tx.Inputs {
			if u, ok := bc.utxoSet.Get(in.PreviousOutput); ok {
				spentScripts = append(spentScripts, u.Script)
			}
		}
	}
	cfilter := BuildBlockFilter(block, spentScripts)
	var prevCFHeader [32]byte
	if block.Header.Height > 0 {
		if h, err := bc.db.Get(cfheaderKey(block.Header.PreviousHash)); err == nil && len(h) == 32 {
			copy(prevCFHeader[:], h)
		}
	}
	cfheader := FilterHeader(FilterHash(cfilter), prevCFHeader)

	if err := ValidateBlock(block, prevHeader, bc.utxoSet, bc.params); err != nil {
		return fmt.Errorf("block validation: %w", err)
	}

	parentWork := bc.getChainWork(block.Header.PreviousHash)
	newChainWork := new(big.Int).Add(parentWork, compactWork(block.Header.Bits))

	batch := bc.db.NewBatch()
	batch.Put(blockKey(hash), block.Header.Serialize())
	batch.Put(blockTxsKey(hash), primitives.SerializeTransactions(block.Txs))
	batch.Put(heightKey(block.Header.Height), hash[:])
	batch.Put(cfilterKey(hash), cfilter)
	batch.Put(cfheaderKey(hash), cfheader[:])
	putChainWork(batch, hash, newChainWork)
	batch.Put([]byte(storage.KeyBestTip), hash[:])
	for _, tx := range block.Txs {
		txid := tx.TxID()
		batch.Put(txIndexKey(txid), hash[:])
	}
	indexBlockAddresses(batch, block)
	if err := batch.Write(); err != nil {
		return fmt.Errorf("write block: %w", err)
	}
	if err := bc.utxoSet.Apply(block); err != nil {
		return fmt.Errorf("apply utxo: %w", err)
	}
	bc.tip = block.Header
	bc.height = block.Header.Height
	return nil
}

// compactWork returns the proof-of-work this block contributed to the
// chain, computed from its compact-bits target per Bitcoin's standard
// formula: work = 2^256 / (target + 1).
func compactWork(bits uint32) *big.Int {
	target := consensus.CompactToBig(bits)
	if target.Sign() <= 0 {
		return big.NewInt(0)
	}
	// work = (2^256) / (target + 1)
	twoTo256 := new(big.Int).Lsh(big.NewInt(1), 256)
	denom := new(big.Int).Add(target, big.NewInt(1))
	return new(big.Int).Div(twoTo256, denom)
}

// chainworkKey is the per-block cumulative-work storage key.
func chainworkKey(hash [32]byte) []byte {
	k := make([]byte, len(storage.PrefixChainWork)+32)
	copy(k, []byte(storage.PrefixChainWork))
	copy(k[len(storage.PrefixChainWork):], hash[:])
	return k
}

// getChainWork reads the cumulative chainwork stored for a block.
// Returns a zero *big.Int if the block has no stored work (e.g. side-chain
// blocks that were never promoted, or the genesis block itself).
func (bc *Blockchain) getChainWork(hash [32]byte) *big.Int {
	raw, err := bc.db.Get(chainworkKey(hash))
	if err != nil || len(raw) == 0 {
		return big.NewInt(0)
	}
	return new(big.Int).SetBytes(raw)
}

// ChainWork is the exported getter for the cumulative chainwork at a given
// block hash. Used by RPC handlers to surface the tip's total work in
// getblockchaininfo.
func (bc *Blockchain) ChainWork(hash [32]byte) *big.Int {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.getChainWork(hash)
}

// putChainWork persists cumulative chainwork for a block in the given batch.
// Storage is big-endian raw bytes — cheap to compare byte-for-byte since
// strlen is fixed once enough work accumulates.
func putChainWork(batch storage.Batch, hash [32]byte, work *big.Int) {
	batch.Put(chainworkKey(hash), work.Bytes())
}

// computeBranchChainWork traces back from startHash along PreviousHash
// pointers and returns the cumulative chainwork: the sum of each block's
// compactWork(Bits) from genesis to startHash inclusive. Lets us compare
// side-chain tips against the main tip even when we only know the block
// headers, not the cumulative work.
//
// Caller must hold bc.mu.
func (bc *Blockchain) computeBranchChainWork(startHash [32]byte) (*big.Int, error) {
	total := big.NewInt(0)
	cur := startHash
	for {
		// If we have the precomputed cumulative work cached, use it and stop.
		if existing := bc.getChainWork(cur); existing.Sign() > 0 {
			return new(big.Int).Add(total, existing), nil
		}
		hdr, err := bc.GetBlockHeader(cur)
		if err != nil {
			return nil, fmt.Errorf("walk back at %x: %w", cur, err)
		}
		total.Add(total, compactWork(hdr.Bits))
		if hdr.Height == 0 {
			return total, nil
		}
		cur = hdr.PreviousHash
	}
}

// findCommonAncestor walks two hash chains backwards from their respective
// tips until they meet. Returns the common-ancestor hash plus the forward
// path from that ancestor → mainTip (exclusive of ancestor) and ancestor →
// sideTip (exclusive of ancestor). Used by reorgToSideBranch to decide
// which blocks to revert and which to connect.
//
// Caller must hold bc.mu.
func (bc *Blockchain) findCommonAncestor(mainTip, sideTip [32]byte) (ancestor [32]byte, mainPath, sidePath [][32]byte, err error) {
	mainSeen := map[[32]byte]struct{}{}
	// Walk mainTip back to genesis, remembering every hash.
	cur := mainTip
	for {
		mainSeen[cur] = struct{}{}
		hdr, herr := bc.GetBlockHeader(cur)
		if herr != nil {
			return [32]byte{}, nil, nil, fmt.Errorf("main walk at %x: %w", cur, herr)
		}
		if hdr.Height == 0 {
			break
		}
		cur = hdr.PreviousHash
	}
	// Walk sideTip back until we hit a hash also on the main chain.
	cur = sideTip
	for {
		if _, ok := mainSeen[cur]; ok {
			ancestor = cur
			break
		}
		sidePath = append([][32]byte{cur}, sidePath...) // prepend, so path is ancestor→tip order
		hdr, herr := bc.GetBlockHeader(cur)
		if herr != nil {
			return [32]byte{}, nil, nil, fmt.Errorf("side walk at %x: %w", cur, herr)
		}
		if hdr.Height == 0 {
			return [32]byte{}, nil, nil, fmt.Errorf("no common ancestor: side chain reaches genesis without meeting main")
		}
		cur = hdr.PreviousHash
	}
	// Build mainPath: from tip back to (exclusive of) ancestor, then reverse.
	cur = mainTip
	for cur != ancestor {
		mainPath = append([][32]byte{cur}, mainPath...) // ancestor→tip order
		hdr, _ := bc.GetBlockHeader(cur)
		cur = hdr.PreviousHash
	}
	return ancestor, mainPath, sidePath, nil
}

// reorgToSideBranch disconnects the main chain back to the common ancestor
// with sideTip, then reconnects the side-branch blocks in order. On any
// failure during reconnect, rolls the main chain back to where it was.
//
// Caller must hold bc.mu in write mode. Expects every block on mainPath
// and sidePath to already be persisted under blockKey/blockTxsKey — i.e.
// every side-chain block came through storeSideChainBlockLocked first.
func (bc *Blockchain) reorgToSideBranch(sideTip [32]byte) error {
	ancestor, mainPath, sidePath, err := bc.findCommonAncestor(bc.tip.Hash(), sideTip)
	if err != nil {
		return fmt.Errorf("reorg: common ancestor: %w", err)
	}

	// Disconnect every main-chain block from tip back to (exclusive of)
	// ancestor. Order: top-down. UTXOSet.Revert requires the block body.
	disconnected := make([]*primitives.Block, 0, len(mainPath))
	for i := len(mainPath) - 1; i >= 0; i-- {
		h := mainPath[i]
		blk, err := bc.getBlockLocked(h)
		if err != nil {
			return fmt.Errorf("reorg: load main block %x: %w", h, err)
		}
		if err := bc.utxoSet.Revert(blk); err != nil {
			return fmt.Errorf("reorg: revert %x: %w", h, err)
		}
		disconnected = append(disconnected, blk)
	}
	// Roll bc.tip back to the ancestor so applyLocked has the right basis.
	ancestorHdr, err := bc.GetBlockHeader(ancestor)
	if err != nil {
		return fmt.Errorf("reorg: load ancestor header: %w", err)
	}
	bc.tip = *ancestorHdr
	bc.height = ancestorHdr.Height

	// Reconnect side-branch blocks forward. If any block fails to apply,
	// unwind: revert everything we applied, then re-apply the original main
	// chain. applyLocked writes new chainwork; putChainWork is called below.
	applied := 0
	for _, h := range sidePath {
		blk, err := bc.getBlockLocked(h)
		if err != nil {
			bc.rollbackReorg(disconnected, sidePath[:applied])
			return fmt.Errorf("reorg: load side block %x: %w", h, err)
		}
		if err := bc.applyLocked(blk); err != nil {
			bc.rollbackReorg(disconnected, sidePath[:applied])
			return fmt.Errorf("reorg: apply side block %x: %w", h, err)
		}
		// Record cumulative work.
		parentWork := bc.getChainWork(blk.Header.PreviousHash)
		newWork := new(big.Int).Add(parentWork, compactWork(blk.Header.Bits))
		batch := bc.db.NewBatch()
		putChainWork(batch, h, newWork)
		if err := batch.Write(); err != nil {
			return fmt.Errorf("reorg: write chainwork for %x: %w", h, err)
		}
		applied++
	}
	return nil
}

// rollbackReorg restores the main chain after a failed reorg attempt. It
// disconnects every side-branch block we applied, then reconnects the
// original disconnected blocks. Best-effort — if something here fails too,
// we log and leave the operator to recover from a snapshot.
func (bc *Blockchain) rollbackReorg(originalMain []*primitives.Block, appliedSide [][32]byte) {
	// Revert everything we applied from the side branch (top-down).
	for i := len(appliedSide) - 1; i >= 0; i-- {
		blk, err := bc.getBlockLocked(appliedSide[i])
		if err != nil {
			return
		}
		_ = bc.utxoSet.Revert(blk)
	}
	// Re-apply the original main chain in ancestor→tip order. disconnected
	// was filled tip→ancestor, so reverse.
	for i := len(originalMain) - 1; i >= 0; i-- {
		_ = bc.applyLocked(originalMain[i])
	}
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

// calcExpectedBits returns the required compact difficulty target for a block
// at the given height using LWMA. blockTimestamp is the candidate block's
// own timestamp, used only by the AllowMinDifficultyBlocks testnet escape
// valve. Callers that don't yet know the block's timestamp (e.g. the miner)
// should pass time.Now().Unix(). Must be called with bc.mu held.
//
//   - height 0 (genesis): returns params.GenesisBits unchanged.
//   - 1 ≤ height ≤ LWMAWindow: returns params.PowLimitBits. During ramp-up any
//     target up to pow-limit is valid, so miners can find blocks from genesis
//     regardless of the chosen GenesisBits.
//   - AllowMinDifficultyBlocks is set AND blockTimestamp > prev + 2*BlockTime:
//     returns PowLimitBits (testnet never-stuck rule).
//   - otherwise: recalculates every block via LWMA over the last LWMAWindow+1
//     headers ending at prevHeader.
func (bc *Blockchain) calcExpectedBits(height uint64, prevHeader *primitives.BlockHeader, blockTimestamp int64) (uint32, error) {
	if height == 0 {
		return bc.params.GenesisBits, nil
	}
	if height <= consensus.LWMAWindow {
		return bc.params.PowLimitBits, nil
	}
	if bc.params.AllowMinDifficultyBlocks && prevHeader != nil &&
		blockTimestamp > prevHeader.Timestamp+2*bc.params.BlockTime {
		return bc.params.PowLimitBits, nil
	}

	window, err := bc.fetchPrevHeaderWindow(prevHeader, consensus.LWMAWindow+1)
	if err != nil {
		return 0, fmt.Errorf("fetch lwma window at height %d: %w", height, err)
	}
	return consensus.NextRequiredBitsLWMA(window, bc.params.BlockTime, bc.params.PowLimitBits), nil
}

// fetchPrevHeaderWindow returns up to count headers ending at (and including)
// endHeader, ordered oldest → newest. Walks backward via PreviousHash. If the
// chain is shorter than count, returns what's available (still ordered
// oldest → newest).
func (bc *Blockchain) fetchPrevHeaderWindow(endHeader *primitives.BlockHeader, count int) ([]*primitives.BlockHeader, error) {
	if endHeader == nil || count <= 0 {
		return nil, nil
	}
	out := make([]*primitives.BlockHeader, 0, count)
	cur := endHeader
	for i := 0; i < count; i++ {
		out = append(out, cur)
		if cur.Height == 0 {
			break
		}
		prev, err := bc.GetBlockHeader(cur.PreviousHash)
		if err != nil {
			return nil, fmt.Errorf("walk prev from height %d: %w", cur.Height, err)
		}
		cur = prev
	}
	// Reverse to oldest → newest.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// GetBlockFilter returns the stored BIP-158 compact block filter for hash,
// or an error if none is indexed for that block. Blocks ingested before
// filter-persistence was added have no stored filter; the caller (typically
// the RPC handler) can fall back to building one on demand.
func (bc *Blockchain) GetBlockFilter(hash [32]byte) ([]byte, error) {
	return bc.db.Get(cfilterKey(hash))
}

// cfilterKey returns the storage key for a compact block filter.
func cfilterKey(hash [32]byte) []byte {
	key := make([]byte, len(storage.PrefixCFilter)+32)
	copy(key, []byte(storage.PrefixCFilter))
	copy(key[len(storage.PrefixCFilter):], hash[:])
	return key
}

// cfheaderKey returns the storage key for a BIP-157 filter header.
func cfheaderKey(hash [32]byte) []byte {
	key := make([]byte, len(storage.PrefixCFHeader)+32)
	copy(key, []byte(storage.PrefixCFHeader))
	copy(key[len(storage.PrefixCFHeader):], hash[:])
	return key
}

// GetFilterHeader returns the persisted BIP-157 filter-header commitment
// for hash, or an error if the block wasn't ingested with a filter header.
func (bc *Blockchain) GetFilterHeader(hash [32]byte) ([32]byte, error) {
	data, err := bc.db.Get(cfheaderKey(hash))
	if err != nil {
		return [32]byte{}, err
	}
	if len(data) != 32 {
		return [32]byte{}, fmt.Errorf("filter header: corrupt length %d", len(data))
	}
	var out [32]byte
	copy(out[:], data)
	return out, nil
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

// indexBlockAddresses writes address-index entries for every standard output
// template in the block. Every output maps to a 20-byte identifier that's
// stable across address formats for the same recipient:
//
//   P2PKH   (25 bytes, "M…" base58):  index by scriptPubKey's 20-byte pkh
//   P2WPKH  (22 bytes, "mlrt1q…"):    index by scriptPubKey's 20-byte pkh
//   P2TR    (34 bytes, "mlrt1p…"):    index by Hash160 of the 32-byte xonly
//
// P2PKH and P2WPKH derived from the same key produce the same pkh, so they
// share index entries. P2TR uses a different key (the tweaked output key),
// which we fold into the same 20-byte namespace via Hash160 — callers query
// by computing the same 20-byte derivation on the client side.
func indexBlockAddresses(batch storage.Batch, block *primitives.Block) {
	height := block.Header.Height
	for _, tx := range block.Txs {
		txid := tx.TxID()
		for _, out := range tx.Outputs {
			if hash, ok := primitives.ExtractP2PKHHash(out.ScriptPubKey); ok {
				batch.Put(addrIndexKey(hash, height, txid), []byte{})
				continue
			}
			if hash, ok := primitives.ExtractP2WPKHHash(out.ScriptPubKey); ok {
				batch.Put(addrIndexKey(hash, height, txid), []byte{})
				continue
			}
			if xonly, ok := primitives.ExtractP2TRKey(out.ScriptPubKey); ok {
				// Fold 32-byte taproot key into the 20-byte namespace via
				// Hash160 so all address types share a single index.
				hash := crypto.Hash160(xonly[:])
				batch.Put(addrIndexKey(hash, height, txid), []byte{})
			}
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
