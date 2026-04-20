package crypto

import (
	"bytes"
	"testing"
)

func TestSchnorrSignVerify(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	xonly, err := XOnlyPubKey(pub)
	if err != nil {
		t.Fatalf("XOnlyPubKey: %v", err)
	}
	if len(xonly) != 32 {
		t.Fatalf("xonly pubkey length: got %d, want 32", len(xonly))
	}

	msg := Hash256([]byte("malairt test message"))
	sig, err := SchnorrSign(priv, msg[:])
	if err != nil {
		t.Fatalf("SchnorrSign: %v", err)
	}
	if len(sig) != 64 {
		t.Errorf("schnorr signature length: got %d, want 64", len(sig))
	}
	if !SchnorrVerify(xonly, msg[:], sig) {
		t.Error("valid signature must verify")
	}

	// Tampered message must not verify.
	bad := msg
	bad[0] ^= 1
	if SchnorrVerify(xonly, bad[:], sig) {
		t.Error("tampered message must not verify")
	}

	// Tampered signature must not verify.
	badSig := append([]byte(nil), sig...)
	badSig[5] ^= 1
	if SchnorrVerify(xonly, msg[:], badSig) {
		t.Error("tampered signature must not verify")
	}
}

func TestSchnorrSign_DifferentMessagesDifferentSignatures(t *testing.T) {
	priv, _, _ := GenerateKeyPair()
	m1 := Hash256([]byte("one"))
	m2 := Hash256([]byte("two"))
	s1, err := SchnorrSign(priv, m1[:])
	if err != nil {
		t.Fatal(err)
	}
	s2, err := SchnorrSign(priv, m2[:])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(s1, s2) {
		t.Error("different messages must produce different signatures")
	}
}

func TestSchnorrVerify_InputValidation(t *testing.T) {
	_, pub, _ := GenerateKeyPair()
	xonly, _ := XOnlyPubKey(pub)

	// Wrong-length inputs must return false rather than panic.
	if SchnorrVerify(xonly[:31], make([]byte, 32), make([]byte, 64)) {
		t.Error("short pubkey must not verify")
	}
	if SchnorrVerify(xonly, make([]byte, 31), make([]byte, 64)) {
		t.Error("short message must not verify")
	}
	if SchnorrVerify(xonly, make([]byte, 32), make([]byte, 63)) {
		t.Error("short signature must not verify")
	}
}

func TestXOnlyPubKey_CompressedRoundTrip(t *testing.T) {
	_, pub, _ := GenerateKeyPair()
	x1, err := XOnlyPubKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	// Re-pass the x-only bytes — should be accepted and return the same value.
	x2, err := XOnlyPubKey(x1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(x1, x2) {
		t.Error("XOnlyPubKey must be idempotent")
	}
	if !bytes.Equal(pub[1:], x1) {
		t.Error("x-only bytes must equal bytes 1..33 of the compressed pubkey")
	}
}
