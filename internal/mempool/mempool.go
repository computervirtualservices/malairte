// Package mempool provides an in-memory pool for unconfirmed transactions.
//
// The pool supports full replace-by-fee (RBF): any unconfirmed transaction may
// be replaced by a new transaction that spends one or more of the same
// outpoints, provided the replacement pays a strictly higher feerate AND
// enough absolute fee to cover its own bandwidth at the min-relay feerate.
// No BIP-125 opt-in flag — every transaction is replaceable by default,
// matching the 2026-era Bitcoin Core default.
package mempool

import (
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/computervirtualservices/malairte/internal/primitives"
)

// MinRelayFeeAtomsPerVByte is the minimum fee an RBF replacement must pay
// *beyond* the replaced transactions' total — covers the bandwidth cost of
// propagating the replacement.
const MinRelayFeeAtomsPerVByte = 1

// RBFFeerateBumpNumerator / Denominator encode the 1.1× feerate bump rule
// (BIP-125 rule 4, retained in full-RBF): newFeerate ≥ oldFeerate × 1.1.
const (
	RBFFeerateBumpNumerator   = 11
	RBFFeerateBumpDenominator = 10
)

// poolEntry is one transaction's full mempool record.
type poolEntry struct {
	tx      *primitives.Transaction
	fee     int64 // atoms
	vsize   int   // weight / 4 (rounded up)
	feerate int64 // atoms per vbyte, pre-computed for sort + RBF comparisons
}

// TxPool is an in-memory pool of unconfirmed transactions awaiting confirmation.
// All methods are safe for concurrent use.
type TxPool struct {
	mu      sync.RWMutex
	entries map[[32]byte]*poolEntry
	// outpoints maps each spent UTXO back to the txid that spends it.
	// Presence of an entry here means "this outpoint is already claimed by a
	// mempool tx"; a new candidate whose inputs collide is only accepted
	// under RBF.
	outpoints map[primitives.OutPoint][32]byte
}

// NewTxPool creates an empty transaction pool.
func NewTxPool() *TxPool {
	return &TxPool{
		entries:   make(map[[32]byte]*poolEntry),
		outpoints: make(map[primitives.OutPoint][32]byte),
	}
}

// Add inserts a transaction into the pool at the given absolute fee (in atoms).
// Callers are expected to compute the fee by looking up each input's prevout
// against the UTXO set (sum of input values minus sum of output values).
//
// If any input conflicts with an existing mempool tx, Add applies the full-RBF
// rules: the replacement must pay ≥ 1.1× the conflicting txs' combined
// feerate AND ≥ (combined fee + newVsize × MinRelayFeeAtomsPerVByte) in
// absolute terms. On success, all conflicting txs are evicted.
func (p *TxPool) Add(tx *primitives.Transaction, feeAtoms int64) error {
	if tx == nil {
		return errors.New("cannot add nil transaction")
	}
	if tx.IsCoinbase() {
		return errors.New("coinbase transactions cannot be added to the mempool")
	}
	if len(tx.Inputs) == 0 {
		return errors.New("transaction has no inputs")
	}
	if len(tx.Outputs) == 0 {
		return errors.New("transaction has no outputs")
	}
	if feeAtoms < 0 {
		return errors.New("fee must be non-negative")
	}
	for i, out := range tx.Outputs {
		if out.Value <= 0 {
			return fmt.Errorf("transaction output has non-positive value at index %d", i)
		}
	}

	txid := tx.TxID()
	// vsize = ceil(weight / 4). Using integer arithmetic.
	vsize := (tx.Weight() + 3) / 4
	if vsize < 1 {
		vsize = 1
	}
	feerate := feeAtoms / int64(vsize)

	p.mu.Lock()
	defer p.mu.Unlock()

	if _, exists := p.entries[txid]; exists {
		return errors.New("transaction already in mempool")
	}

	// Collect conflicting existing txids — each unique txid once.
	conflictSet := make(map[[32]byte]struct{})
	for _, in := range tx.Inputs {
		if existing, ok := p.outpoints[in.PreviousOutput]; ok {
			conflictSet[existing] = struct{}{}
		}
	}

	if len(conflictSet) == 0 {
		// Fast path: no RBF needed.
		p.insertLocked(txid, &poolEntry{tx: tx, fee: feeAtoms, vsize: vsize, feerate: feerate})
		return nil
	}

	// RBF path: aggregate the conflicting entries' fee and feerate.
	var (
		sumConflictFee   int64
		sumConflictVSize int
	)
	for cid := range conflictSet {
		ce := p.entries[cid]
		sumConflictFee += ce.fee
		sumConflictVSize += ce.vsize
	}
	// Compare the NEW tx's feerate against the aggregate old feerate.
	// Old aggregate feerate = sumFee / sumVSize.
	// Rule 1 (bump): newFeerate ≥ oldFeerate × 11/10.
	// Cross-multiply to avoid division:
	//   newFeerate * sumConflictVSize * 10 ≥ sumConflictFee * 11
	lhs := int64(feerate) * int64(sumConflictVSize) * int64(RBFFeerateBumpDenominator)
	rhs := sumConflictFee * int64(RBFFeerateBumpNumerator)
	if lhs < rhs {
		return fmt.Errorf("RBF rejected: feerate %d atoms/vB fails 1.1× bump over %d atoms/vB",
			feerate, sumConflictFee/int64(sumConflictVSize))
	}
	// Rule 2 (bandwidth): absolute fee covers old fee + newVsize × minRelay.
	minFee := sumConflictFee + int64(vsize)*MinRelayFeeAtomsPerVByte
	if feeAtoms < minFee {
		return fmt.Errorf("RBF rejected: fee %d < required %d (replaced %d + %d vbytes bandwidth)",
			feeAtoms, minFee, sumConflictFee, vsize)
	}

	// Accepted — evict every conflict, then insert the replacement.
	for cid := range conflictSet {
		p.removeLocked(cid)
	}
	p.insertLocked(txid, &poolEntry{tx: tx, fee: feeAtoms, vsize: vsize, feerate: feerate})
	return nil
}

// insertLocked adds e to every index. Caller must hold p.mu for writing.
func (p *TxPool) insertLocked(txid [32]byte, e *poolEntry) {
	p.entries[txid] = e
	for _, in := range e.tx.Inputs {
		p.outpoints[in.PreviousOutput] = txid
	}
}

// removeLocked removes txid from every index and cascades to any mempool
// children that spent this tx's outputs. Use this when the parent's outputs
// no longer exist anywhere — RBF evictions, explicit user Remove. Caller
// must hold p.mu for writing.
//
// For block-confirmation removal (parent's outputs are now in the UTXO set,
// so children are still valid), use removeConfirmedLocked instead.
func (p *TxPool) removeLocked(txid [32]byte) {
	e, ok := p.entries[txid]
	if !ok {
		return
	}
	p.deleteEntryLocked(txid, e)

	// Cascade: every other mempool tx that referenced an output of this tx
	// must also be removed. We scan by constructing each possible outpoint
	// this tx produced and checking the outpoint index.
	for i := range e.tx.Outputs {
		op := primitives.OutPoint{TxID: txid, Index: uint32(i)}
		childID, hasChild := p.outpoints[op]
		if !hasChild {
			continue
		}
		// Recursive: child may itself have descendants.
		p.removeLocked(childID)
	}
}

// removeConfirmedLocked removes a transaction that has just been included in
// a confirmed block. Unlike removeLocked this does NOT cascade to children:
// the parent's outputs have transitioned from "mempool-only" to "live in the
// UTXO set", so any child that spends them is still valid and stays in the
// pool. The child's cached fee record is unchanged — input values didn't
// move, only their source of truth did.
func (p *TxPool) removeConfirmedLocked(txid [32]byte) {
	e, ok := p.entries[txid]
	if !ok {
		return
	}
	p.deleteEntryLocked(txid, e)
}

// deleteEntryLocked removes a single entry from both indexes. It does not
// touch children. Shared by removeLocked (cascading path) and
// removeConfirmedLocked (confirmation path).
func (p *TxPool) deleteEntryLocked(txid [32]byte, e *poolEntry) {
	for _, in := range e.tx.Inputs {
		// Only clear the outpoint entry if it currently points to this tx.
		// An earlier RBF eviction might already have rerouted it.
		if owner, ok := p.outpoints[in.PreviousOutput]; ok && owner == txid {
			delete(p.outpoints, in.PreviousOutput)
		}
	}
	delete(p.entries, txid)
}

// Remove removes a transaction by txid.
// Called when a transaction is included in a confirmed block.
// No-op if the transaction is not in the pool.
func (p *TxPool) Remove(txid [32]byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.removeLocked(txid)
}

// RemoveBlock removes all transactions that the given block confirmed. Uses
// the confirmation path (no cascade) — children of a confirmed parent are
// preserved because their inputs now reference live UTXOs instead of mempool
// outputs. CPFP children specifically benefit: the parent is gone from the
// pool but its high-feerate child remains eligible for the next block.
func (p *TxPool) RemoveBlock(block *primitives.Block) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, tx := range block.Txs {
		p.removeConfirmedLocked(tx.TxID())
	}
}

// Has returns true if txid is present in the pool.
func (p *TxPool) Has(txid [32]byte) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, exists := p.entries[txid]
	return exists
}

// Get returns a transaction by its txid, along with a boolean indicating
// whether it was found.
func (p *TxPool) Get(txid [32]byte) (*primitives.Transaction, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	e, exists := p.entries[txid]
	if !exists {
		return nil, false
	}
	return e.tx, true
}

// GetSorted returns up to maxCount transactions sorted by feerate descending.
// This is the order the mining template assembler walks when filling a block.
func (p *TxPool) GetSorted(maxCount int) []*primitives.Transaction {
	p.mu.RLock()
	defer p.mu.RUnlock()

	entries := make([]*poolEntry, 0, len(p.entries))
	for _, e := range p.entries {
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].feerate != entries[j].feerate {
			return entries[i].feerate > entries[j].feerate
		}
		// Tiebreaker: lower vsize first (more fee per block capacity used).
		return entries[i].vsize < entries[j].vsize
	})

	if maxCount > len(entries) {
		maxCount = len(entries)
	}
	result := make([]*primitives.Transaction, maxCount)
	for i := 0; i < maxCount; i++ {
		result[i] = entries[i].tx
	}
	return result
}

// Count returns the number of transactions currently in the pool.
func (p *TxPool) Count() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.entries)
}

// Size returns the approximate total byte size of all serialized transactions
// in the pool. Used for the `-max-mempool` DoS cap.
func (p *TxPool) Size() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	total := 0
	for _, e := range p.entries {
		total += len(e.tx.Serialize())
	}
	return total
}

// GetAll returns a copy of all transactions in the pool (unsorted).
func (p *TxPool) GetAll() []*primitives.Transaction {
	p.mu.RLock()
	defer p.mu.RUnlock()
	result := make([]*primitives.Transaction, 0, len(p.entries))
	for _, e := range p.entries {
		result = append(result, e.tx)
	}
	return result
}

// FeeOf returns the recorded fee (atoms) and feerate (atoms/vbyte) for a
// mempool tx, or (0, 0, false) if it's not present.
func (p *TxPool) FeeOf(txid [32]byte) (fee int64, feerate int64, ok bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	e, exists := p.entries[txid]
	if !exists {
		return 0, 0, false
	}
	return e.fee, e.feerate, true
}

// GetOutput returns the TxOutput referenced by op when op points to a
// transaction already in the mempool. Used by callers that need to compute
// the fee of a child transaction whose parent is still unconfirmed (CPFP):
// they look first in the UTXO set, then fall back to this method.
//
// Returns (zero-value output, false) if op.TxID is not in the pool, or
// op.Index is out of range for the referenced transaction.
func (p *TxPool) GetOutput(op primitives.OutPoint) (primitives.TxOutput, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	e, exists := p.entries[op.TxID]
	if !exists {
		return primitives.TxOutput{}, false
	}
	if op.Index >= uint32(len(e.tx.Outputs)) {
		return primitives.TxOutput{}, false
	}
	return e.tx.Outputs[op.Index], true
}
