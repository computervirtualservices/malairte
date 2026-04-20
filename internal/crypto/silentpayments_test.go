package crypto

import (
	"bytes"
	"testing"

	btcec "github.com/btcsuite/btcd/btcec/v2"
)

// TestSilentPayment_AddressRoundTrip proves an encoded silent-payment
// address decodes back to byte-identical scan and spend keys.
func TestSilentPayment_AddressRoundTrip(t *testing.T) {
	scanPriv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	spendPriv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	orig, err := NewSilentPaymentAddress(scanPriv, spendPriv)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := orig.Encode(SilentPaymentHRPMainnet)
	if err != nil {
		t.Fatal(err)
	}
	if len(addr) < len(SilentPaymentHRPMainnet)+2 {
		t.Fatalf("address too short: %q", addr)
	}
	if !bytes.HasPrefix([]byte(addr), []byte(SilentPaymentHRPMainnet+"1")) {
		t.Errorf("expected HRP prefix, got %q", addr)
	}
	got, err := DecodeSilentPaymentAddress(SilentPaymentHRPMainnet, addr)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Version != orig.Version {
		t.Errorf("version: got %d want %d", got.Version, orig.Version)
	}
	if got.ScanKey != orig.ScanKey {
		t.Error("scan key mismatch after round-trip")
	}
	if got.SpendKey != orig.SpendKey {
		t.Error("spend key mismatch after round-trip")
	}
}

func TestSilentPayment_WrongHRPRejected(t *testing.T) {
	scanPriv, _, _ := GenerateKeyPair()
	spendPriv, _, _ := GenerateKeyPair()
	a, _ := NewSilentPaymentAddress(scanPriv, spendPriv)
	mainAddr, _ := a.Encode(SilentPaymentHRPMainnet)

	// Decoding under testnet's HRP must fail.
	if _, err := DecodeSilentPaymentAddress(SilentPaymentHRPTestnet, mainAddr); err == nil {
		t.Error("mainnet address must not decode under testnet HRP")
	}
}

// TestSilentPayment_SenderReceiverRoundTrip is the core correctness test.
// It simulates:
//   - The recipient publishes a silent-payment address.
//   - The sender has two inputs with known privkeys; it derives an output
//     key for payment index 0.
//   - The receiver (who knows scanPriv) computes the tweak from the tx's
//     PUBLIC inputs, reconstructs the output key, and checks it against
//     the sender's output.
//   - The receiver computes the spend scalar and verifies the pubkey of
//     that scalar equals the output key (so it can actually spend).
func TestSilentPayment_SenderReceiverRoundTrip(t *testing.T) {
	scanPriv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	spendPriv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	addr, err := NewSilentPaymentAddress(scanPriv, spendPriv)
	if err != nil {
		t.Fatal(err)
	}

	// Sender side: two inputs.
	a1, a1Pub, _ := GenerateKeyPair()
	a2, a2Pub, _ := GenerateKeyPair()
	inputPrivs := [][]byte{a1, a2}
	inputPubs := [][]byte{a1Pub, a2Pub}

	// Canonical outpoint (in practice the lex-smallest of all inputs). For
	// the round-trip it only matters that both sides use the same value.
	var txid [32]byte
	copy(txid[:], []byte{0x11, 0x22, 0x33})
	vout := uint32(0)

	outputKey, err := DeriveSilentPaymentOutput(inputPrivs, txid, vout, addr, 0)
	if err != nil {
		t.Fatalf("DeriveSilentPaymentOutput: %v", err)
	}
	if len(outputKey) != 32 {
		t.Fatalf("output key length: got %d, want 32", len(outputKey))
	}

	// Receiver side: derive the tweak and reconstruct the output key.
	tweak, err := ScanForSilentPayment(scanPriv, inputPubs, txid, vout, 0)
	if err != nil {
		t.Fatalf("ScanForSilentPayment: %v", err)
	}

	// Reconstruct P = B_spend + tweak·G using a throwaway derivation: we
	// compute the compound private key and check its pubkey matches the
	// sender's output key.
	dSpend, err := SilentPaymentSpendScalar(spendPriv, tweak)
	if err != nil {
		t.Fatal(err)
	}
	spendPub, err := PubKeyFromPrivKey(dSpend)
	if err != nil {
		t.Fatal(err)
	}
	// The sender's output is an x-only key; our full pubkey's bytes [1:33]
	// should match (possibly after y-parity correction).
	// BIP-340 uses the even-y representative — so if the derived pubkey has
	// odd y, negate dSpend and re-derive. The resulting x-coordinate must
	// match outputKey either way.
	if !bytes.Equal(spendPub[1:33], outputKey) {
		t.Errorf("reconstructed pubkey x ≠ output key:\n got %x\nwant %x",
			spendPub[1:33], outputKey)
	}
}

func TestSilentPayment_DifferentKsProduceDifferentOutputs(t *testing.T) {
	// Two payments to the same address in the same tx must produce
	// DIFFERENT output keys — that's the whole point of the k index.
	scanPriv, _, _ := GenerateKeyPair()
	spendPriv, _, _ := GenerateKeyPair()
	addr, _ := NewSilentPaymentAddress(scanPriv, spendPriv)

	a1, _, _ := GenerateKeyPair()
	var txid [32]byte
	copy(txid[:], []byte{0xAA})
	k0, err := DeriveSilentPaymentOutput([][]byte{a1}, txid, 0, addr, 0)
	if err != nil {
		t.Fatal(err)
	}
	k1, err := DeriveSilentPaymentOutput([][]byte{a1}, txid, 0, addr, 1)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k0, k1) {
		t.Error("payments at k=0 and k=1 must produce different output keys")
	}
}

func TestSilentPayment_WrongScanKeyNoMatch(t *testing.T) {
	// A receiver who doesn't own scanPriv gets a tweak, but reconstructing
	// B_spend + t·G will not match the real output key — the shared secret
	// derives from the wrong scan scalar.
	scanPriv, _, _ := GenerateKeyPair()
	spendPriv, _, _ := GenerateKeyPair()
	addr, _ := NewSilentPaymentAddress(scanPriv, spendPriv)

	a1, a1Pub, _ := GenerateKeyPair()
	var txid [32]byte
	copy(txid[:], []byte{0xBB})

	outputKey, err := DeriveSilentPaymentOutput([][]byte{a1}, txid, 0, addr, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Different scan key → different tweak.
	wrongScan, _, _ := GenerateKeyPair()
	wrongTweak, err := ScanForSilentPayment(wrongScan, [][]byte{a1Pub}, txid, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	dWrong, _ := SilentPaymentSpendScalar(spendPriv, wrongTweak)
	wrongPub, _ := PubKeyFromPrivKey(dWrong)
	if bytes.Equal(wrongPub[1:33], outputKey) {
		t.Error("wrong scan key must not reproduce the output key")
	}
}

// Sanity-check that btcec's scalar multiply behaves the way silentpayments.go
// assumes (input_hash · a · B_scan, computed on either side, gives the same
// shared point). Pure unit test of the algebra; if this ever breaks,
// the round-trip test will too, but this one pinpoints the cause.
func TestSilentPayment_AlgebraDiffieHellmanSymmetric(t *testing.T) {
	a, _, _ := GenerateKeyPair()
	b, _, _ := GenerateKeyPair()
	// Compute a·B and b·A via btcec primitives and check x-coords match.
	var aScalar, bScalar btcec.ModNScalar
	var aBytes, bBytes [32]byte
	copy(aBytes[:], a)
	copy(bBytes[:], b)
	aScalar.SetBytes(&aBytes)
	bScalar.SetBytes(&bBytes)

	// A = a·G, B = b·G
	var A, B btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(&aScalar, &A)
	btcec.ScalarBaseMultNonConst(&bScalar, &B)

	var aB, bA btcec.JacobianPoint
	btcec.ScalarMultNonConst(&aScalar, &B, &aB)
	btcec.ScalarMultNonConst(&bScalar, &A, &bA)
	aB.ToAffine()
	bA.ToAffine()

	var xA, xB [32]byte
	aB.X.PutBytesUnchecked(xA[:])
	bA.X.PutBytesUnchecked(xB[:])
	if xA != xB {
		t.Error("ECDH symmetry broken: a·B ≠ b·A at x-coord — btcec changed")
	}
}
