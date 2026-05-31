package hdwallet

import (
	"encoding/hex"
	"testing"
)

// Canonical BIP39 test vector (Trezor), passphrase "TREZOR".
func TestBIP39VectorAllZeros(t *testing.T) {
	entropy, _ := hex.DecodeString("00000000000000000000000000000000")
	mnemonic, err := EntropyToMnemonic(entropy)
	if err != nil {
		t.Fatalf("EntropyToMnemonic: %v", err)
	}
	want := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	if mnemonic != want {
		t.Fatalf("mnemonic mismatch:\n got: %s\nwant: %s", mnemonic, want)
	}

	seed := MnemonicToSeed(mnemonic, "TREZOR")
	wantSeed := "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
	if got := hex.EncodeToString(seed); got != wantSeed {
		t.Fatalf("seed mismatch:\n got: %s\nwant: %s", got, wantSeed)
	}
}

func TestBIP39VectorAllSevens(t *testing.T) {
	entropy, _ := hex.DecodeString("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f")
	mnemonic, err := EntropyToMnemonic(entropy)
	if err != nil {
		t.Fatalf("EntropyToMnemonic: %v", err)
	}
	want := "legal winner thank year wave sausage worth useful legal winner thank yellow"
	if mnemonic != want {
		t.Fatalf("mnemonic mismatch:\n got: %s\nwant: %s", mnemonic, want)
	}
}

func TestBIP39Vector256Bit(t *testing.T) {
	entropy, _ := hex.DecodeString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	mnemonic, err := EntropyToMnemonic(entropy)
	if err != nil {
		t.Fatalf("EntropyToMnemonic: %v", err)
	}
	want := "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"
	if mnemonic != want {
		t.Fatalf("256-bit mnemonic mismatch:\n got: %s\nwant: %s", mnemonic, want)
	}
}

func TestValidateMnemonic(t *testing.T) {
	good := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	if !ValidateMnemonic(good) {
		t.Error("expected valid mnemonic to validate")
	}
	// Last word changed → checksum fails.
	bad := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
	if ValidateMnemonic(bad) {
		t.Error("expected bad-checksum mnemonic to fail")
	}
	// Not a wordlist word.
	if ValidateMnemonic("zzzz abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about") {
		t.Error("expected non-wordlist mnemonic to fail")
	}
	// Wrong length.
	if ValidateMnemonic("abandon about") {
		t.Error("expected wrong-length mnemonic to fail")
	}
}

func TestNewMnemonicRoundTrips(t *testing.T) {
	for _, bits := range []int{128, 256} {
		m, err := NewMnemonic(bits)
		if err != nil {
			t.Fatalf("NewMnemonic(%d): %v", bits, err)
		}
		if !ValidateMnemonic(m) {
			t.Errorf("generated %d-bit mnemonic failed validation: %q", bits, m)
		}
	}
}
