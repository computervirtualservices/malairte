package signer

import (
	"encoding/hex"
	"errors"
	"testing"
)

// Canonical BIP32 "Test Vector 1" extended public keys (seed 000102…0f).
// Source: BIP-0032 specification. We use them to prove CKDpub (non-hardened
// public-key derivation) and serialization match the reference exactly.
const (
	xpubM0H           = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
	xpubM0H1          = "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
	xpubM0H1_2H       = "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"
	xpubM0H1_2H_2     = "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"
	xpubM0H1_2H_2_1e9 = "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
	xprvM0H           = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
)

// parseHelper parses an xpub and fails the test on error.
func parseHelper(t *testing.T, s string) *ExtendedPubKey {
	t.Helper()
	k, err := ParseExtendedPubKey(s)
	if err != nil {
		t.Fatalf("ParseExtendedPubKey(%s): %v", s, err)
	}
	return k
}

func TestCKDpubMatchesBIP32Vectors(t *testing.T) {
	cases := []struct {
		name     string
		parent   string
		index    uint32
		expected string
	}{
		{"m/0H -> m/0H/1", xpubM0H, 1, xpubM0H1},
		{"m/0H/1/2H -> .../2", xpubM0H1_2H, 2, xpubM0H1_2H_2},
		{"m/0H/1/2H/2 -> .../1000000000", xpubM0H1_2H_2, 1_000_000_000, xpubM0H1_2H_2_1e9},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parent := parseHelper(t, tc.parent)
			want := parseHelper(t, tc.expected)

			child, err := parent.Child(tc.index)
			if err != nil {
				t.Fatalf("Child(%d): %v", tc.index, err)
			}

			if got, exp := hex.EncodeToString(child.PubKey), hex.EncodeToString(want.PubKey); got != exp {
				t.Errorf("child pubkey mismatch\n got: %s\nwant: %s", got, exp)
			}
			if got, exp := hex.EncodeToString(child.ChainCode), hex.EncodeToString(want.ChainCode); got != exp {
				t.Errorf("child chain code mismatch\n got: %s\nwant: %s", got, exp)
			}
			if child.ChildNum != tc.index {
				t.Errorf("child number = %d, want %d", child.ChildNum, tc.index)
			}
			if child.Depth != want.Depth {
				t.Errorf("child depth = %d, want %d", child.Depth, want.Depth)
			}
		})
	}
}

func TestDerivePathEquivalentToChainedChild(t *testing.T) {
	// m/0H/1/2H/2/1000000000 reached from m/0H/1/2H in two non-hardened steps.
	root := parseHelper(t, xpubM0H1_2H)
	want := parseHelper(t, xpubM0H1_2H_2_1e9)

	got, err := root.DerivePath(2, 1_000_000_000)
	if err != nil {
		t.Fatalf("DerivePath: %v", err)
	}
	if hex.EncodeToString(got.PubKey) != hex.EncodeToString(want.PubKey) {
		t.Errorf("DerivePath pubkey mismatch")
	}
	if hex.EncodeToString(got.ChainCode) != hex.EncodeToString(want.ChainCode) {
		t.Errorf("DerivePath chain code mismatch")
	}
}

func TestHardenedDerivationFromPublicFails(t *testing.T) {
	parent := parseHelper(t, xpubM0H)
	if _, err := parent.Child(hardenedOffset); !errors.Is(err, ErrHardenedFromPublic) {
		t.Fatalf("expected ErrHardenedFromPublic, got %v", err)
	}
	if _, err := parent.Child(hardenedOffset + 5); !errors.Is(err, ErrHardenedFromPublic) {
		t.Fatalf("expected ErrHardenedFromPublic for offset+5, got %v", err)
	}
}

func TestParseRejectsExtendedPrivateKey(t *testing.T) {
	if _, err := ParseExtendedPubKey(xprvM0H); err == nil {
		t.Fatal("expected ParseExtendedPubKey to reject an xprv, got nil error")
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	for _, s := range []string{"", "not-base58-!!!", "xpubShort"} {
		if _, err := ParseExtendedPubKey(s); err == nil {
			t.Errorf("expected error parsing %q, got nil", s)
		}
	}
}
