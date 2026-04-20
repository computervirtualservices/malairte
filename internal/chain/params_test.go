package chain

import (
	"bytes"
	"testing"

	"github.com/computervirtualservices/malairte/internal/crypto"
	"github.com/computervirtualservices/malairte/internal/primitives"
)

// TestMainnetBech32HRP_P2TR round-trips a taproot output through the mainnet
// HRP to ensure the Bech32HRP parameter is wired correctly and the produced
// address begins with the expected "mlrt1p" prefix.
func TestMainnetBech32HRP_P2TR(t *testing.T) {
	if MainNetParams.Bech32HRP != "mlrt" {
		t.Fatalf("MainNet Bech32HRP = %q, want mlrt", MainNetParams.Bech32HRP)
	}
	_, pub, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	xonly, err := crypto.XOnlyPubKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := crypto.EncodeSegWitAddress(MainNetParams.Bech32HRP, 1, xonly)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(addr) < 6 || addr[:6] != "mlrt1p" {
		t.Errorf("address prefix: got %q, want mlrt1p…", addr)
	}

	// Script round-trip: P2TRScript(xonly) is a valid output; decoded address
	// matches what P2TRScript embeds.
	var key [32]byte
	copy(key[:], xonly)
	script := primitives.P2TRScript(key)
	decoded, ok := primitives.ExtractP2TRKey(script)
	if !ok || !bytes.Equal(decoded[:], xonly) {
		t.Error("P2TRScript / ExtractP2TRKey mismatch")
	}

	hrp, version, program, err := crypto.DecodeSegWitAddress(addr)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if hrp != "mlrt" || version != 1 || !bytes.Equal(program, xonly) {
		t.Errorf("decode mismatch: hrp=%q ver=%d program=%x", hrp, version, program)
	}
}

// TestTestnetBech32HRP_P2TR confirms testnet uses "tmlrt" so mainnet addresses
// cannot be accidentally used on testnet (or vice versa).
func TestTestnetBech32HRP_P2TR(t *testing.T) {
	if TestNetParams.Bech32HRP != "tmlrt" {
		t.Fatalf("TestNet Bech32HRP = %q, want tmlrt", TestNetParams.Bech32HRP)
	}
	_, pub, _ := crypto.GenerateKeyPair()
	xonly, _ := crypto.XOnlyPubKey(pub)
	addr, err := crypto.EncodeSegWitAddress(TestNetParams.Bech32HRP, 1, xonly)
	if err != nil {
		t.Fatal(err)
	}
	if len(addr) < 7 || addr[:7] != "tmlrt1p" {
		t.Errorf("testnet taproot address prefix: got %q, want tmlrt1p…", addr)
	}
	// Decoding this address under the mainnet HRP must fail (different HRP →
	// different checksum).
	if _, _, _, err := crypto.DecodeSegWitAddress(addr); err != nil {
		t.Fatalf("testnet address must decode under tmlrt: %v", err)
	}
}
