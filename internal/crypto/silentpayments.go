package crypto

import (
	"encoding/binary"
	"errors"
	"fmt"

	btcec "github.com/btcsuite/btcd/btcec/v2"
	btcschnorr "github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// BIP-352 Silent Payments.
//
// A silent payment address is a SINGLE static value a recipient publishes
// once. Senders use it to derive a fresh, unique P2TR output per payment —
// the chain shows only unrelated x-only taproot keys, never the recipient's
// published address. Address reuse is impossible; receipt history can't be
// clustered by an external observer.
//
// TWO-KEY STRUCTURE: the recipient owns a scan key (b_scan) and a spend key
// (b_spend). Their public counterparts (B_scan, B_spend) are both packed
// into the address. Only b_scan is needed to SCAN for incoming payments —
// a watching-only / cold-wallet separation where b_spend never touches the
// hot wallet.
//
// SENDER FLOW
//   1. Collect the private keys of all inputs being spent (a_1, …, a_n).
//      Sum them modulo the curve order: a = Σ a_i.
//   2. Identify the "canonical input": smallest lex outpoint. Its txid+vout
//      feeds an `input_hash` tagged hash.
//   3. Compute shared secret point S = input_hash · a · B_scan.
//   4. For payment index k (0, 1, 2, …), compute tweak
//      t_k = tagged_hash("BIP0352/SharedSecret", S || k).
//   5. Output key P = B_spend + t_k · G. Pay to P2TR(P).
//
// RECEIVER FLOW (scanning a candidate tx)
//   1. Compute sum of the tx's INPUT public keys A = Σ A_i and the same
//      `input_hash`. (Both derivable from chain data + the tx.)
//   2. Compute S = b_scan · input_hash · A.
//   3. For k = 0, 1, 2, … try t_k = tagged_hash("BIP0352/SharedSecret", S || k)
//      and check whether B_spend + t_k·G matches any output key in the tx.
//   4. On match, the scalar that spends this output is d_spend = b_spend + t_k (mod n).
//
// The scheme's security rests on ECDH + the Schnorr/BIP-340 keyspace; there
// are no new crypto primitives. This implementation layers on top of the
// existing btcec secp256k1 library.

// SilentPaymentVersion identifies future tweaks to the address format /
// derivation rules. Version 0 is the BIP-352 original spec.
const SilentPaymentVersion byte = 0

// SilentPaymentHRPMainnet is the bech32m HRP for mainnet silent payment
// addresses ("sp"). Testnet would use "tsp". Addresses encode as
// <hrp>1<version char><66-byte payload: 33+33 compressed pubkeys>.
const (
	SilentPaymentHRPMainnet = "sp"
	SilentPaymentHRPTestnet = "tsp"
)

// SilentPaymentAddress is the recipient-side data a sender needs: two
// compressed secp256k1 public keys. ScanKey receives ECDH contributions for
// every candidate tx; SpendKey anchors the output-key derivation.
type SilentPaymentAddress struct {
	Version  byte
	ScanKey  [33]byte // compressed pubkey
	SpendKey [33]byte // compressed pubkey
}

// NewSilentPaymentAddress constructs an address from raw 32-byte scan and
// spend private keys. Caller keeps the secrets; this is a convenience for
// tests and wallet code.
func NewSilentPaymentAddress(scanPriv, spendPriv []byte) (*SilentPaymentAddress, error) {
	if len(scanPriv) != 32 || len(spendPriv) != 32 {
		return nil, errors.New("silent-payment: both private keys must be 32 bytes")
	}
	sp, err := PubKeyFromPrivKey(spendPriv)
	if err != nil {
		return nil, fmt.Errorf("silent-payment spend pubkey: %w", err)
	}
	sc, err := PubKeyFromPrivKey(scanPriv)
	if err != nil {
		return nil, fmt.Errorf("silent-payment scan pubkey: %w", err)
	}
	if len(sp) != 33 || len(sc) != 33 {
		return nil, errors.New("silent-payment: expected compressed pubkeys")
	}
	a := &SilentPaymentAddress{Version: SilentPaymentVersion}
	copy(a.ScanKey[:], sc)
	copy(a.SpendKey[:], sp)
	return a, nil
}

// Encode produces the bech32m-encoded form: HRP + separator + version +
// base-32 re-encoding of (ScanKey ∥ SpendKey). Mainnet example:
//   sp1qqpxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx…
func (a *SilentPaymentAddress) Encode(hrp string) (string, error) {
	if a.Version != SilentPaymentVersion {
		return "", fmt.Errorf("silent-payment: unsupported version %d", a.Version)
	}
	payload := make([]byte, 66)
	copy(payload[0:33], a.ScanKey[:])
	copy(payload[33:66], a.SpendKey[:])
	data5, err := convertBits(payload, 8, 5, true)
	if err != nil {
		return "", err
	}
	// Prepend the 5-bit version nibble (bech32 alphabet index).
	data := append([]byte{a.Version}, data5...)
	return bech32Encode(hrp, data, SpecBech32m)
}

// DecodeSilentPaymentAddress parses an address under the given HRP and
// returns the three components. Returns an error on HRP mismatch, bad
// bech32m, wrong payload length, or invalid curve points.
func DecodeSilentPaymentAddress(hrp, addr string) (*SilentPaymentAddress, error) {
	decodedHRP, data, spec, err := bech32Decode(addr)
	if err != nil {
		return nil, err
	}
	if decodedHRP != hrp {
		return nil, fmt.Errorf("silent-payment: HRP %q, expected %q", decodedHRP, hrp)
	}
	if spec != SpecBech32m {
		return nil, errors.New("silent-payment: addresses must use bech32m")
	}
	if len(data) < 1 {
		return nil, errors.New("silent-payment: empty payload")
	}
	version := data[0]
	if version != SilentPaymentVersion {
		return nil, fmt.Errorf("silent-payment: unsupported version %d", version)
	}
	payload, err := convertBits(data[1:], 5, 8, false)
	if err != nil {
		return nil, err
	}
	if len(payload) != 66 {
		return nil, fmt.Errorf("silent-payment: expected 66-byte payload, got %d", len(payload))
	}
	// Sanity-check both keys parse as on-curve points.
	if _, err := btcec.ParsePubKey(payload[0:33]); err != nil {
		return nil, fmt.Errorf("silent-payment: scan key invalid: %w", err)
	}
	if _, err := btcec.ParsePubKey(payload[33:66]); err != nil {
		return nil, fmt.Errorf("silent-payment: spend key invalid: %w", err)
	}
	a := &SilentPaymentAddress{Version: version}
	copy(a.ScanKey[:], payload[0:33])
	copy(a.SpendKey[:], payload[33:66])
	return a, nil
}

// DeriveSilentPaymentOutput computes the sender-side output key for a
// payment to recipient. inputPrivKeys is every input's 32-byte private key
// (in input order). canonicalOutpointTxID and canonicalOutpointIndex
// identify the lex-smallest spent outpoint across all inputs — used to
// produce the input_hash. k is the payment index within this transaction
// (0 for the first SP output, 1 for a second, …).
//
// Returns the 32-byte x-only taproot output key the sender should place
// in an OP_1 OP_DATA_32 output script.
func DeriveSilentPaymentOutput(
	inputPrivKeys [][]byte,
	canonicalOutpointTxID [32]byte,
	canonicalOutpointIndex uint32,
	recipient *SilentPaymentAddress,
	k uint32,
) ([]byte, error) {
	a, err := sumScalarsModN(inputPrivKeys)
	if err != nil {
		return nil, fmt.Errorf("silent-payment: sum input keys: %w", err)
	}
	if a.IsZero() {
		return nil, errors.New("silent-payment: summed input scalar is zero")
	}
	inputHash, err := computeInputHash(inputPrivKeys, canonicalOutpointTxID, canonicalOutpointIndex)
	if err != nil {
		return nil, err
	}
	// a' = input_hash * a (mod n)
	aPrime := new(btcec.ModNScalar).Set(a)
	aPrime.Mul(inputHash)

	// S = a' * B_scan
	var bScan btcec.JacobianPoint
	scanPK, err := btcec.ParsePubKey(recipient.ScanKey[:])
	if err != nil {
		return nil, fmt.Errorf("silent-payment: scan key: %w", err)
	}
	scanPK.AsJacobian(&bScan)
	var sharedPoint btcec.JacobianPoint
	btcec.ScalarMultNonConst(aPrime, &bScan, &sharedPoint)
	sharedPoint.ToAffine()

	// t_k = tagged_hash("BIP0352/SharedSecret", S.SerializeCompressed() || k)
	tweak := sharedSecretTweak(&sharedPoint, k)

	// P = B_spend + t_k · G
	spendPK, err := btcec.ParsePubKey(recipient.SpendKey[:])
	if err != nil {
		return nil, fmt.Errorf("silent-payment: spend key: %w", err)
	}
	var bSpend, tG, outPoint btcec.JacobianPoint
	spendPK.AsJacobian(&bSpend)
	btcec.ScalarBaseMultNonConst(tweak, &tG)
	btcec.AddNonConst(&bSpend, &tG, &outPoint)
	outPoint.ToAffine()

	out := make([]byte, 32)
	outPoint.X.PutBytesUnchecked(out)
	return out, nil
}

// ScanForSilentPayment is the receiver-side counterpart. Given the scan
// private key and the same tx context the sender used, returns the tweak
// scalar t_k for payment index k. If t_k·G + B_spend matches any output
// in the tx, the receiver owns that output and the spend scalar is
// (b_spend + t_k) mod n.
//
// scanPriv is the 32-byte scan private key.
// inputPubKeys is the vector of 33-byte compressed pubkeys derived from the
// tx's inputs (for taproot inputs, lift_x of the x-only key).
// canonicalOutpointTxID / Index match the sender's canonical outpoint.
// k is the payment index the receiver is testing (usually 0..some cap).
func ScanForSilentPayment(
	scanPriv []byte,
	inputPubKeys [][]byte,
	canonicalOutpointTxID [32]byte,
	canonicalOutpointIndex uint32,
	k uint32,
) (tweak []byte, err error) {
	if len(scanPriv) != 32 {
		return nil, errors.New("silent-payment: scan key must be 32 bytes")
	}
	A, err := sumPoints(inputPubKeys)
	if err != nil {
		return nil, fmt.Errorf("silent-payment: sum input pubkeys: %w", err)
	}
	inputHash, err := computeInputHashFromPubKeys(inputPubKeys, canonicalOutpointTxID, canonicalOutpointIndex)
	if err != nil {
		return nil, err
	}
	// b' = input_hash · b_scan (mod n)
	var b btcec.ModNScalar
	var scanBytes [32]byte
	copy(scanBytes[:], scanPriv)
	if overflow := b.SetBytes(&scanBytes); overflow != 0 {
		return nil, errors.New("silent-payment: scan key ≥ curve order")
	}
	b.Mul(inputHash)

	var sharedPoint btcec.JacobianPoint
	btcec.ScalarMultNonConst(&b, A, &sharedPoint)
	sharedPoint.ToAffine()

	t := sharedSecretTweak(&sharedPoint, k)
	out := t.Bytes()
	return out[:], nil
}

// ── Helpers ──────────────────────────────────────────────────────────────

// sumScalarsModN returns Σ s_i (mod n) as a ModNScalar. Every input must be
// exactly 32 bytes; overflow is treated as an error.
func sumScalarsModN(privKeys [][]byte) (*btcec.ModNScalar, error) {
	sum := new(btcec.ModNScalar)
	for i, pk := range privKeys {
		if len(pk) != 32 {
			return nil, fmt.Errorf("privkey %d: length %d, want 32", i, len(pk))
		}
		var b [32]byte
		copy(b[:], pk)
		var s btcec.ModNScalar
		if overflow := s.SetBytes(&b); overflow != 0 {
			return nil, fmt.Errorf("privkey %d: ≥ curve order", i)
		}
		sum.Add(&s)
	}
	return sum, nil
}

// sumPoints returns Σ P_i as a *JacobianPoint where each P_i is parsed from
// the corresponding 33-byte compressed pubkey.
func sumPoints(pubKeys [][]byte) (*btcec.JacobianPoint, error) {
	var acc btcec.JacobianPoint
	initialised := false
	for i, pk := range pubKeys {
		parsed, err := btcec.ParsePubKey(pk)
		if err != nil {
			return nil, fmt.Errorf("pubkey %d: %w", i, err)
		}
		var pj btcec.JacobianPoint
		parsed.AsJacobian(&pj)
		if !initialised {
			acc = pj
			initialised = true
			continue
		}
		var next btcec.JacobianPoint
		btcec.AddNonConst(&acc, &pj, &next)
		acc = next
	}
	if !initialised {
		return nil, errors.New("silent-payment: no input pubkeys")
	}
	return &acc, nil
}

// computeInputHash produces the BIP-352 input_hash scalar. For the sender,
// we derive each input's pubkey from its privkey; for the receiver,
// computeInputHashFromPubKeys does the same with the pubkeys directly.
func computeInputHash(
	privKeys [][]byte,
	canonicalTxID [32]byte,
	canonicalIndex uint32,
) (*btcec.ModNScalar, error) {
	pubs := make([][]byte, 0, len(privKeys))
	for _, pk := range privKeys {
		pub, err := PubKeyFromPrivKey(pk)
		if err != nil {
			return nil, err
		}
		pubs = append(pubs, pub)
	}
	return computeInputHashFromPubKeys(pubs, canonicalTxID, canonicalIndex)
}

func computeInputHashFromPubKeys(
	pubKeys [][]byte,
	canonicalTxID [32]byte,
	canonicalIndex uint32,
) (*btcec.ModNScalar, error) {
	A, err := sumPoints(pubKeys)
	if err != nil {
		return nil, err
	}
	A.ToAffine()
	// Serialize A as 33-byte compressed. Parity bit from Y's oddness.
	aBytes := make([]byte, 33)
	if A.Y.IsOdd() {
		aBytes[0] = 0x03
	} else {
		aBytes[0] = 0x02
	}
	A.X.PutBytesUnchecked(aBytes[1:])

	buf := make([]byte, 0, 32+4+33)
	buf = append(buf, canonicalTxID[:]...)
	var idx [4]byte
	binary.LittleEndian.PutUint32(idx[:], canonicalIndex)
	buf = append(buf, idx[:]...)
	buf = append(buf, aBytes...)
	h := TaggedHash("BIP0352/Inputs", buf)

	var s btcec.ModNScalar
	if overflow := s.SetBytes(&h); overflow != 0 {
		return nil, errors.New("silent-payment: input_hash ≥ curve order")
	}
	return &s, nil
}

// sharedSecretTweak = tagged_hash("BIP0352/SharedSecret", compressed(S) || k_le).
func sharedSecretTweak(S *btcec.JacobianPoint, k uint32) *btcec.ModNScalar {
	sBytes := make([]byte, 33)
	if S.Y.IsOdd() {
		sBytes[0] = 0x03
	} else {
		sBytes[0] = 0x02
	}
	S.X.PutBytesUnchecked(sBytes[1:])
	var kBytes [4]byte
	binary.LittleEndian.PutUint32(kBytes[:], k)
	h := TaggedHash("BIP0352/SharedSecret", append(sBytes, kBytes[:]...))
	var s btcec.ModNScalar
	s.SetBytes(&h) // overflow is astronomically unlikely; SetBytes clamps
	return &s
}

// SilentPaymentSpendScalar returns the 32-byte secret d that spends an
// output whose on-chain key is (B_spend + t·G). Receivers call this once
// they've confirmed t produces a match against a tx output key.
func SilentPaymentSpendScalar(spendPriv, tweak []byte) ([]byte, error) {
	if len(spendPriv) != 32 || len(tweak) != 32 {
		return nil, errors.New("silent-payment: spend key and tweak must be 32 bytes each")
	}
	var bp, tk btcec.ModNScalar
	var bpBytes, tkBytes [32]byte
	copy(bpBytes[:], spendPriv)
	copy(tkBytes[:], tweak)
	bp.SetBytes(&bpBytes)
	tk.SetBytes(&tkBytes)
	bp.Add(&tk)
	out := bp.Bytes()
	return out[:], nil
}

// xOnlyPubKeyFromPriv is a small helper: derives the x-only (32-byte) form
// of the compressed pubkey the given 32-byte private key produces. Useful
// for tests that want to check a derived silent-payment output against the
// scan+spend pair that was generated in the same test.
func xOnlyPubKeyFromPriv(priv []byte) ([]byte, error) {
	pub, err := PubKeyFromPrivKey(priv)
	if err != nil {
		return nil, err
	}
	return btcschnorr.SerializePubKey(parsePubUnchecked(pub)), nil
}

// parsePubUnchecked is a thin helper that panics on malformed input. Only
// used internally where the caller has already validated the pubkey bytes.
func parsePubUnchecked(b []byte) *btcec.PublicKey {
	k, err := btcec.ParsePubKey(b)
	if err != nil {
		panic(fmt.Sprintf("parsePubUnchecked: %v", err))
	}
	return k
}
