package chain

import (
	"testing"

	"github.com/computervirtualservices/malairte/internal/consensus"
	"github.com/computervirtualservices/malairte/internal/primitives"
)

// buildMinedBlock builds and mines a block with the given bits.
// Only use with easy bits (e.g. 0x207fffff) — hard targets will take forever.
func buildMinedBlock(t *testing.T, prevHeader *primitives.BlockHeader, bits uint32) *primitives.Block {
	t.Helper()
	height := prevHeader.Height + 1
	params := &TestNetParams
	reward := CalcBlockSubsidy(height, params)
	dummyScript := []byte{0x76, 0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0xac}
	coinbase := primitives.NewCoinbaseTx(height, reward, dummyScript, 0)
	txs := []*primitives.Transaction{coinbase}

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
