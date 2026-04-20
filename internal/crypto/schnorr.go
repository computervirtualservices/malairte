package crypto

import (
	"errors"
	"fmt"

	btcec "github.com/btcsuite/btcd/btcec/v2"
	btcschnorr "github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// BIP-340 Schnorr signatures over secp256k1.
//
// The public key used by Schnorr is the 32-byte x-only encoding of a
// secp256k1 point with the even-y convention: serialise just the x coordinate
// (32 bytes, big-endian) and ignore the y coordinate; verifiers pick the even
// y. Signatures are a fixed 64 bytes.
//
// The project already uses Decred's secp256k1 for ECDSA. Schnorr uses btcec/v2
// because it ships a well-tested BIP-340 implementation; both libraries take
// the same raw 32-byte private-key representation, so keys round-trip without
// conversion.

// SchnorrSign produces a 64-byte BIP-340 signature over msg using secKey.
// secKey must be 32 bytes; msg must be 32 bytes (typically a sighash).
// btcec generates auxiliary randomness internally when the high-level Sign API
// is used, matching the BIP-340 "Default Signing" recommendation.
func SchnorrSign(secKey, msg []byte) ([]byte, error) {
	if len(secKey) != 32 {
		return nil, errors.New("schnorr: private key must be 32 bytes")
	}
	if len(msg) != 32 {
		return nil, errors.New("schnorr: message must be 32 bytes")
	}
	priv, _ := btcec.PrivKeyFromBytes(secKey)
	sig, err := btcschnorr.Sign(priv, msg)
	if err != nil {
		return nil, fmt.Errorf("schnorr sign: %w", err)
	}
	return sig.Serialize(), nil
}

// SchnorrVerify verifies a BIP-340 signature. pubKey is the 32-byte x-only
// encoding (as produced by XOnlyPubKey); sig is 64 bytes; msg is 32 bytes.
// Returns false on any decoding or verification error — callers must treat
// failure as "invalid" without distinguishing reasons.
func SchnorrVerify(pubKey, msg, sig []byte) bool {
	if len(pubKey) != 32 || len(sig) != 64 || len(msg) != 32 {
		return false
	}
	pk, err := btcschnorr.ParsePubKey(pubKey)
	if err != nil {
		return false
	}
	parsed, err := btcschnorr.ParseSignature(sig)
	if err != nil {
		return false
	}
	return parsed.Verify(msg, pk)
}

// XOnlyPubKey converts a 33-byte compressed or 32-byte x-only secp256k1 public
// key into the 32-byte BIP-340 x-only encoding. The returned bytes are the
// x coordinate of the point; BIP-340 verifiers interpret the implied y as the
// even square-root, so a 33-byte compressed key whose y was odd still produces
// the same 32-byte output.
func XOnlyPubKey(pubKey []byte) ([]byte, error) {
	switch len(pubKey) {
	case 32:
		// Already x-only — validate by parsing.
		if _, err := btcschnorr.ParsePubKey(pubKey); err != nil {
			return nil, fmt.Errorf("xonly: %w", err)
		}
		out := make([]byte, 32)
		copy(out, pubKey)
		return out, nil
	case 33:
		pk, err := btcec.ParsePubKey(pubKey)
		if err != nil {
			return nil, fmt.Errorf("xonly: %w", err)
		}
		// SerializeCompressed gives 0x02/0x03 prefix + 32-byte x. Strip the prefix.
		return pk.SerializeCompressed()[1:], nil
	default:
		return nil, fmt.Errorf("xonly: pubkey must be 32 or 33 bytes, got %d", len(pubKey))
	}
}
