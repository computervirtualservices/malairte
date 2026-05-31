package signer

import (
	"testing"

	"github.com/computervirtualservices/malairte/internal/hdwallet"
)

// EIP-55 checksum reference vectors from the EIP-55 specification.
func TestEIP55Checksum(t *testing.T) {
	cases := []string{
		"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
		"0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
		"0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
		"0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
	}
	for _, want := range cases {
		addr := decodeHex20(t, want[2:])
		if got := toEIP55(addr); got != want {
			t.Errorf("toEIP55 mismatch\n got: %s\nwant: %s", got, want)
		}
	}
}

// End-to-end ETH derivation against an ecosystem vector. The canonical
// Hardhat/Foundry mnemonic at m/44'/60'/0'/0/0 is account 0:
// 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266. We derive the account xpub with
// the hdwallet package, parse + CKDpub it exactly as signerd does, and require
// the resulting EIP-55 address matches — proving ETH support is interoperable,
// not merely self-consistent. The only constants are the well-known mnemonic
// and address; nothing is reconstructed by hand.
func TestEthEndToEndHardhatAccount0(t *testing.T) {
	const mnemonic = "test test test test test test test test test test test junk"
	const wantAddr = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

	seed := hdwallet.MnemonicToSeed(mnemonic, "")
	master, err := hdwallet.NewMasterKey(seed)
	if err != nil {
		t.Fatalf("master: %v", err)
	}
	// Account path m/44'/60'/0'.
	account, err := master.Derive(hdwallet.H(44), hdwallet.H(60), hdwallet.H(0))
	if err != nil {
		t.Fatalf("derive account: %v", err)
	}
	xpub, err := account.Neuter().String()
	if err != nil {
		t.Fatalf("serialize xpub: %v", err)
	}

	// Now do exactly what signerd does with only the public xpub.
	acct, err := ParseExtendedPubKey(xpub)
	if err != nil {
		t.Fatalf("parse xpub: %v", err)
	}
	child, err := acct.DerivePath(0, 0) // change 0, index 0
	if err != nil {
		t.Fatalf("derive 0/0: %v", err)
	}
	addr, err := ethAddressFromCompressedPubKey(child.PubKey)
	if err != nil {
		t.Fatalf("eth address: %v", err)
	}
	if addr != wantAddr {
		t.Fatalf("eth address mismatch\n got: %s\nwant: %s", addr, wantAddr)
	}
}

func decodeHex20(t *testing.T, s string) []byte {
	t.Helper()
	if len(s) != 40 {
		t.Fatalf("expected 40 hex chars, got %d", len(s))
	}
	b := make([]byte, 20)
	for i := 0; i < 20; i++ {
		b[i] = hexNibble(t, s[i*2])<<4 | hexNibble(t, s[i*2+1])
	}
	return b
}

func hexNibble(t *testing.T, c byte) byte {
	t.Helper()
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	t.Fatalf("bad hex char %q", c)
	return 0
}
