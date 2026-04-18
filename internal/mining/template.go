// Package mining provides block template assembly and CPU mining.
package mining

import (
	"fmt"
	"time"

	"github.com/computervirtualservices/malairte/internal/chain"
	"github.com/computervirtualservices/malairte/internal/mempool"
	"github.com/computervirtualservices/malairte/internal/primitives"
)

// maxBlockTxs is the maximum number of non-coinbase transactions per block.
const maxBlockTxs = 2000

// BlockTemplate holds everything a miner needs to work on a candidate block.
type BlockTemplate struct {
	// Header is the candidate block header (Nonce should be filled by the miner).
	Header primitives.BlockHeader
	// Txs contains all transactions; Txs[0] is always the coinbase.
	Txs []*primitives.Transaction
	// CoinbaseValue is the total coinbase output value (subsidy + fees) in atoms.
	CoinbaseValue int64
	// Height is the block height being mined.
	Height uint64
	// Bits is the compact difficulty target for this block.
	Bits uint32
}

// NewBlockTemplate assembles a block template for mining the next block.
// coinbaseScript: the P2PKH output script sending the reward to the miner's address.
// extraNonce: counter to vary the coinbase and produce a different merkle root when
// the nonce space is exhausted.
func NewBlockTemplate(bc *chain.Blockchain, pool *mempool.TxPool, coinbaseScript []byte, extraNonce uint64) (*BlockTemplate, error) {
	if bc == nil {
		return nil, fmt.Errorf("blockchain is nil")
	}
	if len(coinbaseScript) == 0 {
		return nil, fmt.Errorf("coinbase script is empty")
	}

	// Get current chain tip info
	bestHeader := bc.BestHeader()
	bestHash := bc.BestHash()
	nextHeight := bc.BestHeight() + 1

	// Compute the difficulty for the new block
	bits, err := bc.CalcNextBits()
	if err != nil {
		return nil, fmt.Errorf("calc next bits: %w", err)
	}

	// Get block subsidy
	params := bc.Params()
	subsidy := chain.CalcBlockSubsidy(nextHeight, params)

	// Select transactions from the mempool and compute their fees via UTXO lookups.
	// Transactions whose inputs reference unconfirmed (not-yet-in-UTXO-set) outputs
	// are skipped rather than included with an unknown fee.
	mempoolTxs := pool.GetSorted(maxBlockTxs)
	utxoSet := bc.UTXOSet()

	var totalFees int64
	includedTxs := make([]*primitives.Transaction, 0, len(mempoolTxs))
	for _, tx := range mempoolTxs {
		fee, err := calcTxFee(tx, utxoSet)
		if err != nil {
			// Skip: inputs not yet confirmed in the UTXO set (chained mempool tx)
			continue
		}
		if fee < 0 {
			// Skip: malformed tx that creates more value than it consumes
			continue
		}
		totalFees += fee
		includedTxs = append(includedTxs, tx)
	}

	coinbaseValue := subsidy + totalFees

	// Create coinbase transaction. If the network has an admin protocol fee,
	// split it off as the first output; the miner gets the remainder.
	coinbaseTx := primitives.NewCoinbaseTx(nextHeight, coinbaseValue, coinbaseScript, extraNonce)
	if adminScript := bc.Params().AdminScript(); adminScript != nil {
		adminFee := bc.Params().AdminFeeAtoms
		if coinbaseValue > adminFee {
			// Reduce miner output, prepend admin output
			coinbaseTx.Outputs[0].Value = coinbaseValue - adminFee
			coinbaseTx.Outputs = append(
				[]primitives.TxOutput{{Value: adminFee, ScriptPubKey: adminScript}},
				coinbaseTx.Outputs...,
			)
		}
	}

	// Assemble transaction list: coinbase first
	allTxs := make([]*primitives.Transaction, 0, 1+len(includedTxs))
	allTxs = append(allTxs, coinbaseTx)
	allTxs = append(allTxs, includedTxs...)

	// Compute merkle root
	merkleRoot := primitives.CalcMerkleRoot(allTxs)

	// Build the header
	header := primitives.BlockHeader{
		Version:      1,
		PreviousHash: bestHash,
		MerkleRoot:   merkleRoot,
		Timestamp:    time.Now().Unix(),
		Bits:         bits,
		Nonce:        0,
		Height:       nextHeight,
	}

	// Ensure timestamp is strictly greater than previous block
	if header.Timestamp <= bestHeader.Timestamp {
		header.Timestamp = bestHeader.Timestamp + 1
	}

	// If the required timestamp would fail the future-timestamp validation check,
	// wait for real time to catch up before returning the template.
	for header.Timestamp > time.Now().Unix()+chain.MaxFutureTimestamp {
		time.Sleep(time.Second)
	}

	return &BlockTemplate{
		Header:        header,
		Txs:           allTxs,
		CoinbaseValue: coinbaseValue,
		Height:        nextHeight,
		Bits:          bits,
	}, nil
}

// calcTxFee computes the miner fee for tx: sum(input values) - sum(output values).
// Returns an error if any input's UTXO is not found in the confirmed UTXO set.
func calcTxFee(tx *primitives.Transaction, utxoSet *chain.UTXOSet) (int64, error) {
	var totalIn int64
	for _, in := range tx.Inputs {
		utxo, found := utxoSet.Get(in.PreviousOutput)
		if !found {
			return 0, fmt.Errorf("UTXO not found: %x:%d",
				in.PreviousOutput.TxID, in.PreviousOutput.Index)
		}
		totalIn += utxo.Value
	}
	var totalOut int64
	for _, out := range tx.Outputs {
		totalOut += out.Value
	}
	return totalIn - totalOut, nil
}
