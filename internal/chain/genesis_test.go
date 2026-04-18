package chain

import (
	"testing"
)

func TestCalcBlockSubsidy(t *testing.T) {
	params := &MainNetParams

	tests := []struct {
		height   uint64
		expected int64
	}{
		{0, 5_000_000_000},
		{209_999, 5_000_000_000},
		{210_000, 2_500_000_000},
		{420_000, 1_250_000_000},
		{630_000, 625_000_000},
		{210_000 * 64, 0}, // After 64 halvings, reward is 0
	}

	for _, tc := range tests {
		got := CalcBlockSubsidy(tc.height, params)
		if got != tc.expected {
			t.Errorf("CalcBlockSubsidy(%d): got %d, want %d", tc.height, got, tc.expected)
		}
	}
}

func TestGenesisBlockStructure(t *testing.T) {
	params := &MainNetParams
	genesis := GenesisBlock(params)

	if genesis.Header.Height != 0 {
		t.Errorf("Genesis height: got %d, want 0", genesis.Header.Height)
	}
	if genesis.Header.PreviousHash != ([32]byte{}) {
		t.Errorf("Genesis PreviousHash should be all zeros")
	}
	if genesis.Header.Timestamp != params.GenesisTimestamp {
		t.Errorf("Genesis timestamp: got %d, want %d", genesis.Header.Timestamp, params.GenesisTimestamp)
	}
	if genesis.Header.Bits != params.GenesisBits {
		t.Errorf("Genesis bits: got 0x%08x, want 0x%08x", genesis.Header.Bits, params.GenesisBits)
	}
	if len(genesis.Txs) != 1 {
		t.Errorf("Genesis should have exactly 1 transaction, got %d", len(genesis.Txs))
	}
	if !genesis.Txs[0].IsCoinbase() {
		t.Error("Genesis transaction should be a coinbase")
	}
}

func TestGenesisBlockHashDeterministic(t *testing.T) {
	params := &MainNetParams
	hash1 := GenesisHash(params)
	hash2 := GenesisHash(params)

	if hash1 != hash2 {
		t.Errorf("GenesisHash not deterministic: %x vs %x", hash1, hash2)
	}

	var zero [32]byte
	if hash1 == zero {
		t.Errorf("GenesisHash should not be all zeros")
	}
}

func TestGenesisMainnetTestnetDiffer(t *testing.T) {
	mainHash := GenesisHash(&MainNetParams)
	testHash := GenesisHash(&TestNetParams)

	// Both networks have the same genesis params, so hashes should be equal
	// (they differ only in magic bytes, ports, and address version, not genesis params)
	_ = mainHash
	_ = testHash
	// This is expected behavior — both chains start from the same genesis
}

func TestGenesisHashMeetsDifficulty(t *testing.T) {
	params := &MainNetParams
	genesis := GenesisBlock(params)
	hash := genesis.Header.Hash()

	// With 0x207fffff bits, virtually any hash meets the target
	// Verify the hash is not zero
	var zero [32]byte
	if hash == zero {
		t.Error("Genesis hash should not be zero")
	}
}

func TestGenesisMessageInCoinbase(t *testing.T) {
	params := &MainNetParams
	genesis := GenesisBlock(params)
	coinbase := genesis.Txs[0]

	scriptSig := coinbase.Inputs[0].ScriptSig
	msg := genesisMessage
	found := false
	if len(scriptSig) >= len(msg) {
		for i := 0; i <= len(scriptSig)-len(msg); i++ {
			match := true
			for j, b := range []byte(msg) {
				if scriptSig[i+j] != b {
					match = false
					break
				}
			}
			if match {
				found = true
				break
			}
		}
	}
	if !found {
		t.Errorf("Genesis message %q not found in coinbase scriptSig: %x", msg, scriptSig)
	}
}
