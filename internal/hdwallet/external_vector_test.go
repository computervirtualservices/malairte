package hdwallet

import (
	"testing"

	"github.com/computervirtualservices/malairte/internal/crypto"
)

// Cross-checks our BIP44 derivation against the rest of the ecosystem using the
// well-known "abandon abandon … about" mnemonic. At m/44'/0'/0'/0/0 standard
// wallets produce BTC address 1LqBGSKuTfwgY8RNb1khRTUcv9Q8eDh8oP. Because an
// MLRT address is the same HASH160 with a different version byte, deriving the
// same path here must yield the identical HASH160 — proving our derivation is
// interoperable, not merely self-consistent.
func TestExternalBIP44Vector(t *testing.T) {
	const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	const knownBTC = "1LqBGSKuTfwgY8RNb1khRTUcv9Q8eDh8oP" // m/44'/0'/0'/0/0

	seed := MnemonicToSeed(mnemonic, "")
	master, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("master: %v", err)
	}
	leaf, err := master.Derive(H(44), H(0), H(0), 0, 0)
	if err != nil {
		t.Fatalf("derive m/44'/0'/0'/0/0: %v", err)
	}

	ourHash := crypto.Hash160(leaf.Neuter().Key) // HASH160(compressed pubkey)

	_, btcPayload, err := crypto.Base58CheckDecode(knownBTC)
	if err != nil {
		t.Fatalf("decode known BTC address: %v", err)
	}
	if len(btcPayload) != 20 {
		t.Fatalf("expected 20-byte hash160 from BTC address, got %d", len(btcPayload))
	}

	for i := 0; i < 20; i++ {
		if ourHash[i] != btcPayload[i] {
			t.Fatalf("hash160 mismatch at byte %d — derivation is NOT BIP44-interoperable", i)
		}
	}
}
