// Package mempool provides an in-memory pool for unconfirmed transactions.
package mempool

import (
	"errors"
	"sort"
	"sync"

	"github.com/malairt/malairt/internal/primitives"
)

// TxPool is an in-memory pool of unconfirmed transactions awaiting confirmation.
// All methods are safe for concurrent use.
type TxPool struct {
	txs map[[32]byte]*primitives.Transaction
	mu  sync.RWMutex
}

// NewTxPool creates an empty transaction pool.
func NewTxPool() *TxPool {
	return &TxPool{
		txs: make(map[[32]byte]*primitives.Transaction),
	}
}

// Add inserts a transaction into the pool.
// Returns an error if the transaction is a duplicate or fails basic validation.
func (p *TxPool) Add(tx *primitives.Transaction) error {
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
	for i, out := range tx.Outputs {
		if out.Value <= 0 {
			return errors.New("transaction output has non-positive value at index " + itoa(i))
		}
	}

	txid := tx.TxID()

	p.mu.Lock()
	defer p.mu.Unlock()

	if _, exists := p.txs[txid]; exists {
		return errors.New("transaction already in mempool")
	}

	p.txs[txid] = tx
	return nil
}

// Remove removes a transaction by txid.
// Called when a transaction is included in a confirmed block.
// No-op if the transaction is not in the pool.
func (p *TxPool) Remove(txid [32]byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.txs, txid)
}

// RemoveBlock removes all transactions that are included in the given block.
func (p *TxPool) RemoveBlock(block *primitives.Block) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, tx := range block.Txs {
		delete(p.txs, tx.TxID())
	}
}

// Has returns true if txid is present in the pool.
func (p *TxPool) Has(txid [32]byte) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, exists := p.txs[txid]
	return exists
}

// Get returns a transaction by its txid, along with a boolean indicating whether it was found.
func (p *TxPool) Get(txid [32]byte) (*primitives.Transaction, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	tx, exists := p.txs[txid]
	return tx, exists
}

// txWithFee pairs a transaction with its total output value (used as fee proxy when UTXOs are not available).
type txWithFee struct {
	tx          *primitives.Transaction
	totalOutput int64
}

// GetSorted returns up to maxCount transactions sorted by total output value descending.
// This is a proxy for fee-based sorting when input values are not readily available.
// Used by the block template assembler.
func (p *TxPool) GetSorted(maxCount int) []*primitives.Transaction {
	p.mu.RLock()
	defer p.mu.RUnlock()

	pairs := make([]txWithFee, 0, len(p.txs))
	for _, tx := range p.txs {
		var totalOut int64
		for _, out := range tx.Outputs {
			totalOut += out.Value
		}
		pairs = append(pairs, txWithFee{tx: tx, totalOutput: totalOut})
	}

	// Sort by total output descending (higher-value txs prioritized)
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].totalOutput > pairs[j].totalOutput
	})

	if maxCount > len(pairs) {
		maxCount = len(pairs)
	}

	result := make([]*primitives.Transaction, maxCount)
	for i := 0; i < maxCount; i++ {
		result[i] = pairs[i].tx
	}
	return result
}

// Count returns the number of transactions currently in the pool.
func (p *TxPool) Count() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.txs)
}

// Size returns the approximate total byte size of all serialized transactions in the pool.
func (p *TxPool) Size() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	total := 0
	for _, tx := range p.txs {
		total += len(tx.Serialize())
	}
	return total
}

// GetAll returns a copy of all transactions in the pool (unsorted).
func (p *TxPool) GetAll() []*primitives.Transaction {
	p.mu.RLock()
	defer p.mu.RUnlock()
	result := make([]*primitives.Transaction, 0, len(p.txs))
	for _, tx := range p.txs {
		result = append(result, tx)
	}
	return result
}

// itoa converts an int to its decimal string representation without fmt.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := [20]byte{}
	pos := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
