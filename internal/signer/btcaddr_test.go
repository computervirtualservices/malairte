package signer

import (
	"encoding/hex"
	"testing"

	"github.com/computervirtualservices/malairte/internal/hdwallet"
)

// BIP173 reference: the pubkey 0279BE667E...17798 (the secp256k1 generator,
// Bitcoin's well-known test pubkey) yields P2WPKH address
// bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 on mainnet. This pins our
// convertBits + bech32 + HASH160 pipeline to the spec.
func TestBTCP2WPKHReferenceVector(t *testing.T) {
	pub, _ := hex.DecodeString("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	got, err := btcP2WPKHFromCompressedPubKey(pub, "bc")
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	const want = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
	if got != want {
		t.Fatalf("p2wpkh mismatch\n got: %s\nwant: %s", got, want)
	}
}

// End-to-end BTC derivation against an ecosystem vector. The canonical
// "abandon abandon … about" mnemonic at m/84'/0'/0'/0/0 (BIP84 native SegWit)
// is the well-known address bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu. We
// derive the account xpub (m/84'/0'/0') with the hdwallet package, then parse +
// CKDpub it exactly as signerd does — proving BTC support is interoperable.
func TestBTCEndToEndBIP84Vector(t *testing.T) {
	const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	const want = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"

	seed := hdwallet.MnemonicToSeed(mnemonic, "")
	master, err := hdwallet.NewMasterKey(seed)
	if err != nil {
		t.Fatalf("master: %v", err)
	}
	account, err := master.Derive(hdwallet.H(84), hdwallet.H(0), hdwallet.H(0))
	if err != nil {
		t.Fatalf("derive account: %v", err)
	}
	xpub, err := account.Neuter().String()
	if err != nil {
		t.Fatalf("serialize xpub: %v", err)
	}

	acct, err := ParseExtendedPubKey(xpub)
	if err != nil {
		t.Fatalf("parse xpub: %v", err)
	}
	child, err := acct.DerivePath(0, 0)
	if err != nil {
		t.Fatalf("derive 0/0: %v", err)
	}
	addr, err := btcP2WPKHFromCompressedPubKey(child.PubKey, "bc")
	if err != nil {
		t.Fatalf("btc address: %v", err)
	}
	if addr != want {
		t.Fatalf("btc address mismatch\n got: %s\nwant: %s", addr, want)
	}
}
