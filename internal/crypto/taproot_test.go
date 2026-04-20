package crypto

import (
	"bytes"
	"testing"
)

// TestTapTweak_PubKeySecKeyConsistency verifies the fundamental BIP-341
// invariant: a signature produced with TapTweakSecKey verifies against the
// output key produced by TapTweakPubKey for the same internal keypair and
// merkle root. This is the property wallets must satisfy to spend what they
// receive.
func TestTapTweak_PubKeySecKeyConsistency(t *testing.T) {
	sec, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	xonly, err := XOnlyPubKey(pub)
	if err != nil {
		t.Fatal(err)
	}

	// No merkle root — pure key-path taproot.
	outKey, _, err := TapTweakPubKey(xonly, nil)
	if err != nil {
		t.Fatalf("TapTweakPubKey: %v", err)
	}
	tweakedSec, err := TapTweakSecKey(sec, nil)
	if err != nil {
		t.Fatalf("TapTweakSecKey: %v", err)
	}

	// Sign a test message with the tweaked secret; it must verify under the
	// tweaked public key.
	msg := Hash256([]byte("tap-tweak consistency"))
	sig, err := SchnorrSign(tweakedSec, msg[:])
	if err != nil {
		t.Fatalf("SchnorrSign: %v", err)
	}
	if !SchnorrVerify(outKey, msg[:], sig) {
		t.Error("taproot-tweaked signature must verify under tweaked output key")
	}
	// A signature made with the *untweaked* key must NOT verify under the
	// tweaked output key — otherwise TapTweak has no effect.
	rawSig, err := SchnorrSign(sec, msg[:])
	if err != nil {
		t.Fatalf("raw SchnorrSign: %v", err)
	}
	if SchnorrVerify(outKey, msg[:], rawSig) {
		t.Error("untweaked signature must not verify under tweaked output key")
	}
}

func TestTapTweak_WithMerkleRoot(t *testing.T) {
	sec, pub, _ := GenerateKeyPair()
	xonly, _ := XOnlyPubKey(pub)

	// Arbitrary 32-byte merkle root — BIP-341's tag+input is a pure hash,
	// so any 32-byte value is acceptable for round-trip testing.
	root := Hash256([]byte("merkle root stand-in"))

	pubA, _, err := TapTweakPubKey(xonly, root[:])
	if err != nil {
		t.Fatalf("TapTweakPubKey(root): %v", err)
	}
	secA, err := TapTweakSecKey(sec, root[:])
	if err != nil {
		t.Fatalf("TapTweakSecKey(root): %v", err)
	}
	msg := Hash256([]byte("with-root"))
	sig, _ := SchnorrSign(secA, msg[:])
	if !SchnorrVerify(pubA, msg[:], sig) {
		t.Error("with-merkle-root tweaked pair must verify")
	}

	// Changing the merkle root must yield a different output key.
	pubB, _, err := TapTweakPubKey(xonly, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(pubA, pubB) {
		t.Error("different merkle roots must produce different output keys")
	}
}

func TestTapTweak_InvalidInputs(t *testing.T) {
	if _, _, err := TapTweakPubKey(make([]byte, 31), nil); err == nil {
		t.Error("TapTweakPubKey must reject wrong-length internal key")
	}
	if _, _, err := TapTweakPubKey(make([]byte, 32), make([]byte, 31)); err == nil {
		t.Error("TapTweakPubKey must reject wrong-length merkle root")
	}
	if _, err := TapTweakSecKey(make([]byte, 31), nil); err == nil {
		t.Error("TapTweakSecKey must reject wrong-length sec key")
	}
}
