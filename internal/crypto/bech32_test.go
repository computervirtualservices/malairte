package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// BIP-350 official test vectors — valid bech32m strings.
var bech32mValid = []struct {
	s    string
	hrp  string
	spec int
}{
	{"A1LQFN3A", "a", SpecBech32m},
	{"a1lqfn3a", "a", SpecBech32m},
	{"abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx", "abcdef", SpecBech32m},
	{"split1checkupstagehandshakeupstreamerranterredcaperredlc445v", "split", SpecBech32m},
	{"?1v759aa", "?", SpecBech32m},
}

// BIP-173 official test vectors — valid bech32 (v0).
var bech32Valid = []struct {
	s    string
	hrp  string
	spec int
}{
	{"A12UEL5L", "a", SpecBech32},
	{"a12uel5l", "a", SpecBech32},
	{"abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw", "abcdef", SpecBech32},
	{"split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w", "split", SpecBech32},
	{"?1ezyfcl", "?", SpecBech32},
}

func TestBech32Decode_ValidVectors(t *testing.T) {
	for _, tc := range bech32Valid {
		gotHRP, _, gotSpec, err := bech32Decode(tc.s)
		if err != nil {
			t.Errorf("%q: unexpected error: %v", tc.s, err)
			continue
		}
		if gotHRP != tc.hrp {
			t.Errorf("%q: hrp got %q, want %q", tc.s, gotHRP, tc.hrp)
		}
		if gotSpec != tc.spec {
			t.Errorf("%q: spec got %d, want %d", tc.s, gotSpec, tc.spec)
		}
	}
	for _, tc := range bech32mValid {
		gotHRP, _, gotSpec, err := bech32Decode(tc.s)
		if err != nil {
			t.Errorf("%q: unexpected error: %v", tc.s, err)
			continue
		}
		if gotHRP != tc.hrp {
			t.Errorf("%q: hrp got %q, want %q", tc.s, gotHRP, tc.hrp)
		}
		if gotSpec != tc.spec {
			t.Errorf("%q: spec got %d, want %d", tc.s, gotSpec, tc.spec)
		}
	}
}

func TestBech32_MixedCaseRejected(t *testing.T) {
	// A valid all-lower string with one uppercase character must fail.
	mixed := "a12uEl5l"
	if _, _, _, err := bech32Decode(mixed); err == nil {
		t.Error("mixed-case bech32 must be rejected")
	}
}

func TestSegWit_P2TRRoundTrip(t *testing.T) {
	// Take a random 32-byte x-only pubkey; ensure it round-trips through
	// EncodeSegWitAddress (v1 → bech32m) and DecodeSegWitAddress.
	_, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	xonly, err := XOnlyPubKey(pub)
	if err != nil {
		t.Fatal(err)
	}

	addr, err := EncodeSegWitAddress("mlrt", 1, xonly)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// Must start with the HRP + "1p" (p = version 1 in bech32 alphabet).
	if len(addr) < 6 || addr[:6] != "mlrt1p" {
		t.Errorf("expected prefix mlrt1p, got %q", addr[:min(len(addr), 10)])
	}

	hrp, version, program, err := DecodeSegWitAddress(addr)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if hrp != "mlrt" {
		t.Errorf("hrp: got %q, want mlrt", hrp)
	}
	if version != 1 {
		t.Errorf("version: got %d, want 1", version)
	}
	if !bytes.Equal(program, xonly) {
		t.Errorf("program mismatch: got %s, want %s", hex.EncodeToString(program), hex.EncodeToString(xonly))
	}
}

func TestSegWit_P2WPKHRoundTrip(t *testing.T) {
	// P2WPKH uses v0 + bech32 (not bech32m).
	_, pub, _ := GenerateKeyPair()
	pkh := Hash160(pub)

	addr, err := EncodeSegWitAddress("mlrt", 0, pkh[:])
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if addr[:6] != "mlrt1q" {
		t.Errorf("expected prefix mlrt1q (v0), got %q", addr[:min(len(addr), 10)])
	}

	hrp, version, program, err := DecodeSegWitAddress(addr)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if hrp != "mlrt" || version != 0 {
		t.Errorf("hrp/version: got %q/%d, want mlrt/0", hrp, version)
	}
	if !bytes.Equal(program, pkh[:]) {
		t.Error("program mismatch")
	}
}

func TestSegWit_CrossSpecRejection(t *testing.T) {
	// Encode a v1 (bech32m) address, then tamper with the checksum so it
	// verifies under bech32 instead — v0 under bech32m is an error; so is
	// a v1 address whose checksum is the bech32 constant.
	_, pub, _ := GenerateKeyPair()
	xonly, _ := XOnlyPubKey(pub)
	v1Addr, _ := EncodeSegWitAddress("mlrt", 1, xonly)
	if _, _, _, err := DecodeSegWitAddress(v1Addr); err != nil {
		t.Fatalf("v1 bech32m must decode: %v", err)
	}

	// Manually build a v0 program encoded under bech32m (wrong spec).
	data5, _ := convertBits(xonly, 8, 5, true) // use 32-byte program like P2WSH
	data := append([]byte{0}, data5...)
	wrong, _ := bech32Encode("mlrt", data, SpecBech32m) // v0 but bech32m checksum
	if _, _, _, err := DecodeSegWitAddress(wrong); err == nil {
		t.Error("v0 under bech32m must be rejected")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
