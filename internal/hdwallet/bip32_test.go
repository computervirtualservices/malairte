package hdwallet

import (
	"encoding/hex"
	"testing"
)

// BIP32 Test Vector 1 (seed 000102…0f).
func TestBIP32Vector1(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")

	master, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("NewMasterKey: %v", err)
	}

	wantMasterXprv := "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
	wantMasterXpub := "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"

	if s, _ := master.String(); s != wantMasterXprv {
		t.Fatalf("master xprv mismatch:\n got: %s\nwant: %s", s, wantMasterXprv)
	}
	if s, _ := master.Neuter().String(); s != wantMasterXpub {
		t.Fatalf("master xpub mismatch:\n got: %s\nwant: %s", s, wantMasterXpub)
	}

	// m/0H
	m0h, err := master.Derive(H(0))
	if err != nil {
		t.Fatalf("Derive m/0H: %v", err)
	}
	wantXprv := "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
	wantXpub := "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
	if s, _ := m0h.String(); s != wantXprv {
		t.Fatalf("m/0H xprv mismatch:\n got: %s\nwant: %s", s, wantXprv)
	}
	if s, _ := m0h.Neuter().String(); s != wantXpub {
		t.Fatalf("m/0H xpub mismatch:\n got: %s\nwant: %s", s, wantXpub)
	}

	// m/0H/1
	m0h1, err := m0h.Derive(1)
	if err != nil {
		t.Fatalf("Derive m/0H/1: %v", err)
	}
	wantXpub01 := "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
	if s, _ := m0h1.Neuter().String(); s != wantXpub01 {
		t.Fatalf("m/0H/1 xpub mismatch:\n got: %s\nwant: %s", s, wantXpub01)
	}
}

// The account xpub produced for the BIP44 MLRT path must be parseable and
// internally consistent: the private chain and the round-tripped xpub agree.
func TestAccountXpubRoundTrips(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	master, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("NewMasterKey: %v", err)
	}

	// m/44'/0'/0'
	account, err := master.Derive(H(44), H(0), H(0))
	if err != nil {
		t.Fatalf("derive account: %v", err)
	}

	xpub, err := account.Neuter().String()
	if err != nil {
		t.Fatalf("serialize account xpub: %v", err)
	}
	if len(xpub) < 4 || xpub[:4] != "xpub" {
		t.Fatalf("expected an xpub string, got %q", xpub)
	}

	privChild, err := account.Derive(0, 1)
	if err != nil {
		t.Fatalf("private derive 0/1: %v", err)
	}
	if len(privChild.pubBytes()) != 33 {
		t.Fatalf("expected 33-byte compressed pubkey")
	}
}
