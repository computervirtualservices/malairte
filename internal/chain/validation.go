package chain

import (
	"errors"
	"fmt"
	"time"

	"github.com/computervirtualservices/malairte/internal/consensus"
	"github.com/computervirtualservices/malairte/internal/primitives"
)

// MaxFutureTimestamp is the maximum number of seconds a block timestamp can
// be in the future relative to the current wall clock time.
const MaxFutureTimestamp = 2 * 60 * 60 // 2 hours

// maxFutureTimestamp is an internal alias kept for use within this package.
const maxFutureTimestamp = MaxFutureTimestamp

// ValidateBlockHeader checks PoW and basic header consistency.
// prevHeader may be nil only for the genesis block (height 0).
func ValidateBlockHeader(header *primitives.BlockHeader, prevHeader *primitives.BlockHeader, params *ChainParams) error {
	// Check that the block hash meets the difficulty target
	hash := header.Hash()
	if !consensus.HashMeetsDifficulty(hash, header.Bits) {
		return fmt.Errorf("block hash %x does not meet difficulty target (bits: %08x)", hash, header.Bits)
	}

	// Genesis block special case
	if header.Height == 0 {
		if header.PreviousHash != ([32]byte{}) {
			return errors.New("genesis block must have zero previous hash")
		}
		return nil
	}

	if prevHeader == nil {
		return errors.New("previous header required for non-genesis block")
	}

	// Check height is exactly prevHeader.Height + 1
	if header.Height != prevHeader.Height+1 {
		return fmt.Errorf("invalid block height: expected %d, got %d", prevHeader.Height+1, header.Height)
	}

	// Check previous hash links correctly
	prevHash := prevHeader.Hash()
	if header.PreviousHash != prevHash {
		return fmt.Errorf("block previous hash mismatch: expected %x, got %x", prevHash, header.PreviousHash)
	}

	// Check timestamp is not too far in the future
	now := time.Now().Unix()
	if header.Timestamp > now+maxFutureTimestamp {
		return fmt.Errorf("block timestamp %d is too far in the future (now: %d)", header.Timestamp, now)
	}

	// Check timestamp is greater than previous block (prevent time regression)
	if header.Timestamp <= prevHeader.Timestamp {
		return fmt.Errorf("block timestamp %d is not greater than previous block timestamp %d",
			header.Timestamp, prevHeader.Timestamp)
	}

	return nil
}

// ValidateBlock performs full block validation including:
//   - Header validation (PoW, height, previous hash linkage)
//   - Exactly one coinbase transaction as the first transaction
//   - Coinbase reward does not exceed CalcBlockSubsidy
//   - Merkle root matches the computed root of all transactions
//   - All non-coinbase transactions are valid against the UTXO set
func ValidateBlock(block *primitives.Block, prevHeader *primitives.BlockHeader, utxo *UTXOSet, params *ChainParams) error {
	// Validate header
	if err := ValidateBlockHeader(&block.Header, prevHeader, params); err != nil {
		return fmt.Errorf("invalid block header: %w", err)
	}

	// Must have at least one transaction (the coinbase)
	if len(block.Txs) == 0 {
		return errors.New("block has no transactions")
	}

	// Enforce block weight limit. Pre-SegWit this is equivalent to a byte-size
	// cap of MaxBlockWeight/WitnessScaleFactor; post-SegWit it prices the
	// witness discount correctly. The check precedes per-tx validation so that
	// a deliberately oversized block is rejected cheaply.
	if params.MaxBlockWeight > 0 {
		if w := block.Weight(); w > params.MaxBlockWeight {
			return fmt.Errorf("block weight %d exceeds maximum %d", w, params.MaxBlockWeight)
		}
	}

	// First transaction must be a coinbase
	if !block.Txs[0].IsCoinbase() {
		return errors.New("first transaction is not a coinbase")
	}

	// No other transaction may be a coinbase
	for i := 1; i < len(block.Txs); i++ {
		if block.Txs[i].IsCoinbase() {
			return fmt.Errorf("transaction %d is a coinbase but is not the first transaction", i)
		}
	}

	// Verify merkle root
	computedMerkleRoot := primitives.CalcMerkleRoot(block.Txs)
	if computedMerkleRoot != block.Header.MerkleRoot {
		return fmt.Errorf("merkle root mismatch: header has %x, computed %x",
			block.Header.MerkleRoot, computedMerkleRoot)
	}

	// Validate coinbase reward
	maxReward := CalcBlockSubsidy(block.Header.Height, params)
	coinbaseTx := block.Txs[0]
	var coinbaseOut int64
	for _, out := range coinbaseTx.Outputs {
		coinbaseOut += out.Value
	}
	if coinbaseOut > maxReward {
		return fmt.Errorf("coinbase output %d exceeds maximum reward %d at height %d",
			coinbaseOut, maxReward, block.Header.Height)
	}

	// BIP-141 witness commitment: every block's coinbase MUST carry a witness
	// commitment output (OP_RETURN 0x24 0xaa21a9ed <32-byte hash>) whose payload
	// equals ComputeWitnessCommitment over the block's transactions. Exempts
	// the genesis block, which has no commitment by construction.
	if block.Header.Height > 0 {
		got, ok := primitives.ExtractWitnessCommitment(coinbaseTx)
		if !ok {
			return errors.New("coinbase missing required witness commitment output")
		}
		want := primitives.ComputeWitnessCommitment(block.Txs)
		if got != want {
			return fmt.Errorf("witness commitment mismatch: got %x, want %x", got, want)
		}
	}

	// Enforce admin protocol fee on every block past genesis: the coinbase
	// must contain at least one output paying ≥ AdminFeeAtoms to the admin
	// address. This is consensus, not policy — invalid blocks are rejected.
	if adminScript := params.AdminScript(); adminScript != nil && block.Header.Height > 0 {
		if !hasOutputToScript(coinbaseTx.Outputs, adminScript, params.AdminFeeAtoms) {
			return fmt.Errorf("coinbase missing required admin fee output of %d atoms to %s",
				params.AdminFeeAtoms, params.AdminAddress)
		}
	}

	// Validate all non-coinbase transactions
	// Track txids of transactions in this block to detect double-spends within block
	spentInBlock := make(map[primitives.OutPoint]struct{})

	for i := 1; i < len(block.Txs); i++ {
		tx := block.Txs[i]

		// Check for double-spend within the block
		for _, in := range tx.Inputs {
			if _, exists := spentInBlock[in.PreviousOutput]; exists {
				return fmt.Errorf("transaction %x double-spends output within block", tx.TxID())
			}
			spentInBlock[in.PreviousOutput] = struct{}{}
		}

		if err := ValidateTx(tx, utxo, block.Header.Height, params); err != nil {
			return fmt.Errorf("invalid transaction %x: %w", tx.TxID(), err)
		}
	}

	return nil
}

// ValidateTx performs transaction-level validation against the UTXO set.
// Checks:
//   - Transaction has at least one input and one output
//   - All inputs reference existing UTXOs
//   - Output values are positive and don't overflow
//   - Input values >= output values (no negative fee)
//   - P2PKH inputs are fully script-verified (signature + pubkey hash);
//     other script types pass permissively until a full interpreter is added
func ValidateTx(tx *primitives.Transaction, utxo *UTXOSet, height uint64, params *ChainParams) error {
	if len(tx.Inputs) == 0 {
		return errors.New("transaction has no inputs")
	}
	if len(tx.Outputs) == 0 {
		return errors.New("transaction has no outputs")
	}

	// Validate output values
	var totalOut int64
	for i, out := range tx.Outputs {
		if out.Value <= 0 {
			return fmt.Errorf("output %d has non-positive value %d", i, out.Value)
		}
		totalOut += out.Value
		if totalOut < 0 {
			return errors.New("output value overflow")
		}
	}

	// Enforce admin protocol fee on every non-coinbase tx: at least one output
	// must pay ≥ AdminFeeAtoms to the admin address. Same consensus rule that
	// applies to coinbases above; ValidateTx is called for non-coinbase txs only.
	if adminScript := params.AdminScript(); adminScript != nil {
		if !hasOutputToScript(tx.Outputs, adminScript, params.AdminFeeAtoms) {
			return fmt.Errorf("transaction missing required admin fee output of %d atoms to %s",
				params.AdminFeeAtoms, params.AdminAddress)
		}
	}

	// First pass: resolve every input's UTXO, verify coinbase maturity, and
	// accumulate totalIn. Also collect each input's scriptPubKey and value
	// into flat vectors for BIP-341 taproot sighash (which commits to every
	// spent UTXO, not just the one at the current input).
	prevoutScripts := make([][]byte, len(tx.Inputs))
	prevoutAmounts := make([]int64, len(tx.Inputs))
	utxoEntries := make([]*UTXO, len(tx.Inputs))
	var totalIn int64
	for i, in := range tx.Inputs {
		utxoEntry, found := utxo.Get(in.PreviousOutput)
		if !found {
			return fmt.Errorf("input %d references non-existent UTXO %x:%d",
				i, in.PreviousOutput.TxID, in.PreviousOutput.Index)
		}
		if utxoEntry.IsCoinbase && height-utxoEntry.Height < 100 {
			return fmt.Errorf("input %d spends immature coinbase output (height %d, current %d)",
				i, utxoEntry.Height, height)
		}
		// BIP-68 relative timelock (block-based variant).
		//
		// Applies when tx.Version ≥ 2. The nSequence field encodes a
		// relative timelock per input unless bit 31 (disable flag) is set.
		// Bit 22 distinguishes block-based (clear) from time-based (set)
		// delays; we implement block-based only, which is the common
		// case — time-based would additionally require reading the
		// prevout's median-time-past, which we don't index yet.
		//
		// For block-based locks: the low 16 bits of nSequence are the
		// minimum number of confirmations the prevout must have before
		// this input may spend it.
		if tx.Version >= 2 {
			const (
				seqDisable = uint32(1) << 31
				seqType    = uint32(1) << 22
			)
			if in.Sequence&seqDisable == 0 && in.Sequence&seqType == 0 {
				required := uint64(in.Sequence & 0x0000ffff)
				if height < utxoEntry.Height+required {
					return fmt.Errorf(
						"input %d: BIP-68 relative timelock not satisfied: "+
							"prevout confirmed at height %d, needs %d confirmations, "+
							"current height %d",
						i, utxoEntry.Height, required, height)
				}
			}
		}
		totalIn += utxoEntry.Value
		if totalIn < 0 {
			return errors.New("input value overflow")
		}
		prevoutScripts[i] = utxoEntry.Script
		prevoutAmounts[i] = utxoEntry.Value
		utxoEntries[i] = utxoEntry
	}

	// Second pass: script execution. Runs after prevouts are assembled so
	// that taproot inputs can commit to the full spent-UTXO vector.
	for i, in := range tx.Inputs {
		if err := ExecuteScript(
			in.ScriptSig,
			utxoEntries[i].Script,
			tx, i,
			utxoEntries[i].Value,
			prevoutScripts,
			prevoutAmounts,
			params.Net,
		); err != nil {
			return fmt.Errorf("input %d script failure: %w", i, err)
		}
		_ = in // keep loop variable referenced for readability
	}

	// Inputs must cover outputs (fee is totalIn - totalOut, must be >= 0)
	if totalIn < totalOut {
		return fmt.Errorf("input value %d less than output value %d", totalIn, totalOut)
	}

	return nil
}

// hasOutputToScript returns true if any output in outs pays at least minValue
// atoms to a scriptPubKey byte-identical to script.
func hasOutputToScript(outs []primitives.TxOutput, script []byte, minValue int64) bool {
	for _, out := range outs {
		if out.Value < minValue {
			continue
		}
		if len(out.ScriptPubKey) != len(script) {
			continue
		}
		match := true
		for i := range script {
			if out.ScriptPubKey[i] != script[i] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
