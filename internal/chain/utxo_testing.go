package chain

import "github.com/computervirtualservices/malairte/internal/primitives"

// InjectForTest writes a UTXO directly to the underlying store, bypassing
// the Apply pipeline. Intended ONLY for unit tests that need to set up a
// specific UTXO state without mining a real block for it. The function
// lives in a non-test file so test code in OTHER packages (e.g. rpc tests)
// can reach it; if this ever gets called from production code the caller
// is misusing the API and the chain state will be inconsistent with block
// history.
func (u *UTXOSet) InjectForTest(utxo *UTXO) {
	op := primitives.OutPoint{TxID: utxo.TxID, Index: utxo.Index}
	_ = u.db.NewBatch() // force a flush of any pending writes
	batch := u.db.NewBatch()
	batch.Put(utxoKey(op), utxo.Serialize())
	_ = batch.Write()
}
