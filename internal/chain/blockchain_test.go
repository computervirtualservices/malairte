package chain

import (
	"strings"
	"testing"

	"github.com/computervirtualservices/malairte/internal/consensus"
	"github.com/computervirtualservices/malairte/internal/crypto"
	"github.com/computervirtualservices/malairte/internal/primitives"
)

// buildMinedBlock builds and mines a block with the given bits.
// Only use with easy bits (e.g. 0x207fffff) — hard targets will take forever.
// The coinbase carries the mandatory BIP-141 witness commitment over the
// final transaction list.
func buildMinedBlock(t *testing.T, prevHeader *primitives.BlockHeader, bits uint32) *primitives.Block {
	t.Helper()
	height := prevHeader.Height + 1
	params := &TestNetParams
	reward := CalcBlockSubsidy(height, params)
	dummyScript := []byte{0x76, 0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0xac}
	coinbase := primitives.NewCoinbaseTx(height, reward, dummyScript, 0)
	txs := []*primitives.Transaction{coinbase}

	// Attach witness commitment over the current tx list (just the coinbase).
	commitment := primitives.ComputeWitnessCommitment(txs)
	coinbase.Outputs = append(coinbase.Outputs, primitives.TxOutput{
		Value:        0,
		ScriptPubKey: primitives.BuildWitnessCommitmentScript(commitment),
	})

	header := primitives.BlockHeader{
		Version:      1,
		PreviousHash: prevHeader.Hash(),
		MerkleRoot:   primitives.CalcMerkleRoot(txs),
		Timestamp:    prevHeader.Timestamp + 1,
		Bits:         bits,
		Nonce:        0,
		Height:       height,
	}
	for !consensus.HashMeetsDifficulty(header.Hash(), bits) {
		header.Nonce++
	}
	return &primitives.Block{Header: header, Txs: txs}
}

// ── tests ─────────────────────────────────────────────────────────────────────

// TestProcessBlock_RejectsMismatchedBits verifies that a block whose Bits field
// does not match the expected network difficulty is rejected.
// The bits check fires before PoW and merkle validation, so no valid PoW is needed.
func TestProcessBlock_RejectsMismatchedBits(t *testing.T) {
	params := new(ChainParams)
	*params = TestNetParams

	bc, err := NewBlockchain(params, newMemDB())
	if err != nil {
		t.Fatalf("NewBlockchain: %v", err)
	}

	genesis := GenesisBlock(params)

	// Build a valid block at height 1 with correct bits, then flip Bits before submitting.
	block := buildMinedBlock(t, &genesis.Header, params.GenesisBits)
	block.Header.Bits = 0x1d00ffff // wrong value — bits check must reject before PoW check

	if err := bc.ProcessBlock(block); err == nil {
		t.Fatal("ProcessBlock accepted block with wrong bits; expected rejection")
	} else {
		t.Logf("correctly rejected: %v", err)
	}
}

// TestProcessBlock_AcceptsCorrectBits verifies that a fully valid block at
// height 1 (with the correct GenesisBits target) is accepted.
func TestProcessBlock_AcceptsCorrectBits(t *testing.T) {
	params := new(ChainParams)
	*params = TestNetParams

	bc, err := NewBlockchain(params, newMemDB())
	if err != nil {
		t.Fatalf("NewBlockchain: %v", err)
	}

	genesis := GenesisBlock(params)
	block := buildMinedBlock(t, &genesis.Header, params.GenesisBits)

	if err := bc.ProcessBlock(block); err != nil {
		t.Fatalf("ProcessBlock rejected block with correct bits: %v", err)
	}
}

// TestProcessBlock_RejectsMissingWitnessCommitment verifies a block whose
// coinbase omits the BIP-141 witness commitment is rejected.
func TestProcessBlock_RejectsMissingWitnessCommitment(t *testing.T) {
	params := new(ChainParams)
	*params = TestNetParams

	bc, err := NewBlockchain(params, newMemDB())
	if err != nil {
		t.Fatalf("NewBlockchain: %v", err)
	}
	genesis := GenesisBlock(params)
	block := buildMinedBlock(t, &genesis.Header, params.GenesisBits)

	// Strip the witness commitment output the helper added.
	cb := block.Txs[0]
	cb.Outputs = cb.Outputs[:len(cb.Outputs)-1]
	block.Header.MerkleRoot = primitives.CalcMerkleRoot(block.Txs)
	// Re-mine after tx mutation.
	block.Header.Nonce = 0
	for !consensus.HashMeetsDifficulty(block.Header.Hash(), block.Header.Bits) {
		block.Header.Nonce++
	}

	if err := bc.ProcessBlock(block); err == nil {
		t.Fatal("ProcessBlock accepted block with no witness commitment; expected rejection")
	} else {
		t.Logf("correctly rejected missing commitment: %v", err)
	}
}

// TestProcessBlock_RejectsTamperedWitnessCommitment verifies a block whose
// commitment payload doesn't match ComputeWitnessCommitment is rejected.
func TestProcessBlock_RejectsTamperedWitnessCommitment(t *testing.T) {
	params := new(ChainParams)
	*params = TestNetParams

	bc, err := NewBlockchain(params, newMemDB())
	if err != nil {
		t.Fatalf("NewBlockchain: %v", err)
	}
	genesis := GenesisBlock(params)
	block := buildMinedBlock(t, &genesis.Header, params.GenesisBits)

	// Flip a bit in the commitment payload (bytes [6:38] of the OP_RETURN).
	cb := block.Txs[0]
	commitOut := &cb.Outputs[len(cb.Outputs)-1]
	commitOut.ScriptPubKey[10] ^= 0x01
	block.Header.MerkleRoot = primitives.CalcMerkleRoot(block.Txs)
	block.Header.Nonce = 0
	for !consensus.HashMeetsDifficulty(block.Header.Hash(), block.Header.Bits) {
		block.Header.Nonce++
	}

	if err := bc.ProcessBlock(block); err == nil {
		t.Fatal("ProcessBlock accepted tampered commitment; expected rejection")
	} else {
		t.Logf("correctly rejected tampered commitment: %v", err)
	}
}

// TestProcessBlock_LastCommitmentWins verifies BIP-141's rule: when a coinbase
// carries multiple witness commitment outputs, the last one must match.
func TestProcessBlock_LastCommitmentWins(t *testing.T) {
	params := new(ChainParams)
	*params = TestNetParams

	bc, err := NewBlockchain(params, newMemDB())
	if err != nil {
		t.Fatalf("NewBlockchain: %v", err)
	}
	genesis := GenesisBlock(params)
	block := buildMinedBlock(t, &genesis.Header, params.GenesisBits)

	cb := block.Txs[0]
	// Insert a GARBAGE commitment BEFORE the real one; real one stays last.
	garbage := primitives.BuildWitnessCommitmentScript([32]byte{0xDE, 0xAD, 0xBE, 0xEF})
	last := cb.Outputs[len(cb.Outputs)-1]
	cb.Outputs = append(cb.Outputs[:len(cb.Outputs)-1],
		primitives.TxOutput{Value: 0, ScriptPubKey: garbage},
		last,
	)
	block.Header.MerkleRoot = primitives.CalcMerkleRoot(block.Txs)
	block.Header.Nonce = 0
	for !consensus.HashMeetsDifficulty(block.Header.Hash(), block.Header.Bits) {
		block.Header.Nonce++
	}

	if err := bc.ProcessBlock(block); err != nil {
		t.Fatalf("block with valid last commitment should be accepted, got: %v", err)
	}
}

// TestAddressIndex_IndexesAllThreeScriptTypes verifies the address indexer
// records P2PKH, P2WPKH, and P2TR outputs so wallets on any address type can
// query their history. All three encodings share the same 20-byte key
// namespace: P2PKH and P2WPKH use the pkh directly, P2TR uses Hash160 of the
// x-only output key.
func TestAddressIndex_IndexesAllThreeScriptTypes(t *testing.T) {
	params := new(ChainParams)
	*params = TestNetParams

	bc, err := NewBlockchain(params, newMemDB())
	if err != nil {
		t.Fatalf("NewBlockchain: %v", err)
	}
	genesis := GenesisBlock(params)

	// Build a block at height 1 with three outputs, one per script type.
	var pkh20 [20]byte
	for i := range pkh20 {
		pkh20[i] = byte(0x70 | i)
	}
	var xonly32 [32]byte
	for i := range xonly32 {
		xonly32[i] = byte(0xC0 | (i % 16))
	}
	p2pkh := primitives.P2PKHScript(pkh20)
	p2wpkh := primitives.P2WPKHScript(pkh20)
	p2tr := primitives.P2TRScript(xonly32)

	dummyScript := []byte{0x76, 0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0xac}
	reward := CalcBlockSubsidy(1, params)
	coinbase := primitives.NewCoinbaseTx(1, reward, dummyScript, 0)
	// Add our three outputs to the coinbase — coinbase outputs are valid
	// "receive" destinations for indexing purposes too.
	coinbase.Outputs = append(coinbase.Outputs,
		primitives.TxOutput{Value: 1, ScriptPubKey: p2pkh},
		primitives.TxOutput{Value: 1, ScriptPubKey: p2wpkh},
		primitives.TxOutput{Value: 1, ScriptPubKey: p2tr},
	)
	// Coinbase needs its subsidy output first; trim to the valid amount
	// (subsidy + 3 atoms) so block validation doesn't reject.
	coinbase.Outputs[0].Value = reward - 3
	txs := []*primitives.Transaction{coinbase}

	commitment := primitives.ComputeWitnessCommitment(txs)
	coinbase.Outputs = append(coinbase.Outputs, primitives.TxOutput{
		Value:        0,
		ScriptPubKey: primitives.BuildWitnessCommitmentScript(commitment),
	})

	header := primitives.BlockHeader{
		Version:      1,
		PreviousHash: genesis.Header.Hash(),
		MerkleRoot:   primitives.CalcMerkleRoot(txs),
		Timestamp:    genesis.Header.Timestamp + 1,
		Bits:         params.GenesisBits,
		Nonce:        0,
		Height:       1,
	}
	for !consensus.HashMeetsDifficulty(header.Hash(), params.GenesisBits) {
		header.Nonce++
	}
	block := &primitives.Block{Header: header, Txs: txs}

	if err := bc.ProcessBlock(block); err != nil {
		t.Fatalf("ProcessBlock: %v", err)
	}

	// Query by each 20-byte identifier and assert a match.
	p2trKey := crypto.Hash160(xonly32[:])
	cases := []struct {
		name string
		key  [20]byte
	}{
		{"P2PKH / P2WPKH shared namespace", pkh20},
		{"P2TR via Hash160(xonly)", p2trKey},
	}
	for _, tc := range cases {
		records, err := bc.GetTransactionsByAddress(tc.key, 10)
		if err != nil {
			t.Errorf("%s: GetTransactionsByAddress: %v", tc.name, err)
			continue
		}
		if len(records) == 0 {
			t.Errorf("%s: no txs returned; address indexer missed the output", tc.name)
		}
	}
}

// TestProcessBlock_SiblingFork_RejectedWhenEqualWork covers the first-seen
// tiebreaker: a competing block at the same height and same bits as the
// current tip has equal PoW; we keep the block we saw first.
func TestProcessBlock_SiblingFork_RejectedWhenEqualWork(t *testing.T) {
	params := new(ChainParams)
	*params = TestNetParams

	bc, err := NewBlockchain(params, newMemDB())
	if err != nil {
		t.Fatal(err)
	}
	genesis := GenesisBlock(params)

	// First block at height 1.
	first := buildMinedBlock(t, &genesis.Header, params.GenesisBits)
	if err := bc.ProcessBlock(first); err != nil {
		t.Fatal(err)
	}

	// A sibling at height 1: same parent, same bits, different coinbase
	// extraNonce so it's a distinct block.
	sibling := buildMinedBlockWithNonce(t, &genesis.Header, params.GenesisBits, 42)
	if sibling.Header.Hash() == first.Header.Hash() {
		t.Fatal("test setup error: sibling == first")
	}
	err = bc.ProcessBlock(sibling)
	if err == nil {
		t.Error("equal-work sibling must be rejected by first-seen rule")
	} else if !strings.Contains(err.Error(), "sibling fork") && !strings.Contains(err.Error(), "does not extend") {
		t.Errorf("unexpected rejection reason: %v", err)
	}
	// Canonical chain should still be `first`.
	if bc.BestHash() != first.Header.Hash() {
		t.Errorf("tip changed on equal-work sibling: got %x want %x",
			bc.BestHash(), first.Header.Hash())
	}
}

// buildMinedBlockWithNonce mines a block with a specific extraNonce so
// callers can produce distinct siblings.
func buildMinedBlockWithNonce(t *testing.T, prevHeader *primitives.BlockHeader, bits uint32, extraNonce uint64) *primitives.Block {
	t.Helper()
	height := prevHeader.Height + 1
	params := &TestNetParams
	reward := CalcBlockSubsidy(height, params)
	dummyScript := []byte{0x76, 0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0xac}
	coinbase := primitives.NewCoinbaseTx(height, reward, dummyScript, extraNonce)
	txs := []*primitives.Transaction{coinbase}
	commitment := primitives.ComputeWitnessCommitment(txs)
	coinbase.Outputs = append(coinbase.Outputs, primitives.TxOutput{
		Value:        0,
		ScriptPubKey: primitives.BuildWitnessCommitmentScript(commitment),
	})
	header := primitives.BlockHeader{
		Version:      1,
		PreviousHash: prevHeader.Hash(),
		MerkleRoot:   primitives.CalcMerkleRoot(txs),
		Timestamp:    prevHeader.Timestamp + 1,
		Bits:         bits,
		Nonce:        0,
		Height:       height,
	}
	for !consensus.HashMeetsDifficulty(header.Hash(), bits) {
		header.Nonce++
	}
	return &primitives.Block{Header: header, Txs: txs}
}

// TestProcessBlock_DeeperFork_StoredButNotReorganised verifies that an
// equal-work deeper fork is persisted for future comparison without
// becoming canonical. Two chains of the same length and same bits should
// leave the first-seen chain canonical.
func TestProcessBlock_DeeperFork_StoredButNotReorganised(t *testing.T) {
	params := new(ChainParams)
	*params = TestNetParams
	bc, err := NewBlockchain(params, newMemDB())
	if err != nil {
		t.Fatal(err)
	}
	genesis := GenesisBlock(params)

	// Main chain: blocks at heights 1 and 2.
	mainA := buildMinedBlockWithNonce(t, &genesis.Header, params.GenesisBits, 0xA0)
	if err := bc.ProcessBlock(mainA); err != nil {
		t.Fatal(err)
	}
	mainB := buildMinedBlockWithNonce(t, &mainA.Header, params.GenesisBits, 0xA1)
	if err := bc.ProcessBlock(mainB); err != nil {
		t.Fatal(err)
	}
	originalTip := bc.BestHash()

	// Side chain: two blocks also descending from the same genesis, but
	// each with a different extraNonce → distinct hashes from the main
	// chain. Equal bits means equal per-block work → equal cumulative work.
	sideA := buildMinedBlockWithNonce(t, &genesis.Header, params.GenesisBits, 0xB0)
	if sideA.Header.Hash() == mainA.Header.Hash() {
		t.Fatal("test setup: side-chain hash collision")
	}
	// First side block is a SIBLING of mainA, so ProcessBlock routes to
	// handleSiblingBlock; equal work → refused.
	err = bc.ProcessBlock(sideA)
	if err == nil {
		t.Error("equal-work sibling must be refused")
	}
	// Second side block descends from the sibling. Its parent is now a
	// stored-but-non-canonical block → handleDeeperFork path.
	sideB := buildMinedBlockWithNonce(t, &sideA.Header, params.GenesisBits, 0xB1)
	err = bc.ProcessBlock(sideB)
	if err == nil || !strings.Contains(err.Error(), "deeper fork stored") {
		t.Errorf("expected 'deeper fork stored' rejection, got: %v", err)
	}
	// Main chain must still be canonical.
	if bc.BestHash() != originalTip {
		t.Errorf("canonical tip changed: got %x, want %x", bc.BestHash(), originalTip)
	}
}

// TestProcessBlock_RejectsOverweightBlock verifies MaxBlockWeight enforcement.
// A block with a weight exceeding params.MaxBlockWeight must be rejected; we
// emulate this by setting MaxBlockWeight absurdly low (100 WU, below the
// ~800 WU a bare coinbase block carries).
func TestProcessBlock_RejectsOverweightBlock(t *testing.T) {
	params := new(ChainParams)
	*params = TestNetParams
	params.MaxBlockWeight = 100 // any real block will exceed this

	bc, err := NewBlockchain(params, newMemDB())
	if err != nil {
		t.Fatalf("NewBlockchain: %v", err)
	}
	genesis := GenesisBlock(params)
	block := buildMinedBlock(t, &genesis.Header, params.GenesisBits)

	if err := bc.ProcessBlock(block); err == nil {
		t.Fatal("ProcessBlock accepted overweight block; expected rejection")
	} else {
		t.Logf("correctly rejected overweight block: %v", err)
	}
}
