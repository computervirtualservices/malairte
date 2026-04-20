package mempool

import (
	"sync"

	"github.com/computervirtualservices/malairte/internal/primitives"
)

// OrphanPool holds transactions that reference parents we haven't seen yet
// (not in the confirmed UTXO set, not in the main mempool). When the missing
// parent finally arrives, the orphan becomes eligible and the caller can
// re-try it.
//
// Bounded in two ways: a per-orphan expiry isn't implemented (a future
// simplification can be "evict oldest when count exceeds cap"), but a hard
// cap prevents a peer from growing the pool without limit. When the cap is
// hit, the newest-inserted orphan wins over an arbitrary existing one.
type OrphanPool struct {
	mu    sync.Mutex
	cap   int
	txs   map[[32]byte]*primitives.Transaction         // child txid → tx
	byPar map[[32]byte]map[[32]byte]struct{}           // parent txid → set of child txids
}

// NewOrphanPool creates a pool that will hold at most cap orphans.
func NewOrphanPool(cap int) *OrphanPool {
	if cap < 1 {
		cap = 100
	}
	return &OrphanPool{
		cap:   cap,
		txs:   make(map[[32]byte]*primitives.Transaction),
		byPar: make(map[[32]byte]map[[32]byte]struct{}),
	}
}

// Add stores tx as an orphan. If the pool is at capacity, evicts one
// existing orphan to make room. Safe to call concurrently.
func (p *OrphanPool) Add(tx *primitives.Transaction) {
	if tx == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	txid := tx.TxID()
	if _, exists := p.txs[txid]; exists {
		return
	}

	if len(p.txs) >= p.cap {
		// Evict the first orphan we iterate over. map iteration order is
		// randomised, which is a sufficient eviction policy here.
		for victim := range p.txs {
			p.removeLocked(victim)
			break
		}
	}

	p.txs[txid] = tx
	for _, in := range tx.Inputs {
		parent := in.PreviousOutput.TxID
		set, ok := p.byPar[parent]
		if !ok {
			set = make(map[[32]byte]struct{})
			p.byPar[parent] = set
		}
		set[txid] = struct{}{}
	}
}

// Release removes and returns every orphan whose parent is parentTxID. The
// caller re-adds each returned tx via the main mempool pathway (which may
// itself generate a new cascade of parent lookups).
func (p *OrphanPool) Release(parentTxID [32]byte) []*primitives.Transaction {
	p.mu.Lock()
	defer p.mu.Unlock()

	set, ok := p.byPar[parentTxID]
	if !ok {
		return nil
	}
	out := make([]*primitives.Transaction, 0, len(set))
	for childID := range set {
		if tx, ok := p.txs[childID]; ok {
			out = append(out, tx)
		}
		p.removeLocked(childID)
	}
	return out
}

// removeLocked clears txid from both indexes. Caller must hold p.mu.
func (p *OrphanPool) removeLocked(txid [32]byte) {
	tx, ok := p.txs[txid]
	if !ok {
		return
	}
	for _, in := range tx.Inputs {
		parent := in.PreviousOutput.TxID
		if set, ok := p.byPar[parent]; ok {
			delete(set, txid)
			if len(set) == 0 {
				delete(p.byPar, parent)
			}
		}
	}
	delete(p.txs, txid)
}

// Count returns the number of orphans currently held.
func (p *OrphanPool) Count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.txs)
}

// Has reports whether a specific tx is currently in the orphan pool.
func (p *OrphanPool) Has(txid [32]byte) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.txs[txid]
	return ok
}
