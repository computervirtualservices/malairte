package signer

import (
	"encoding/hex"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/sha3"
)

// ETHAddressFromCompressedPubKey is the exported entry point used by
// signerd-keygen to encode an Ethereum address from a derived child public key,
// guaranteeing the generator and the running signer agree byte-for-byte.
func ETHAddressFromCompressedPubKey(compressed []byte) (string, error) {
	return ethAddressFromCompressedPubKey(compressed)
}

// ethAddressFromCompressedPubKey derives an EIP-55 checksummed Ethereum address
// (0x…) from a 33-byte compressed secp256k1 public key.
//
// Ethereum address = last 20 bytes of Keccak-256(uncompressed pubkey X||Y),
// then mixed-case checksummed per EIP-55. NOTE: this is *legacy* Keccak-256
// (NewLegacyKeccak256), NOT NIST SHA3-256 — they differ in padding, and using
// the wrong one yields addresses no Ethereum node will recognise.
func ethAddressFromCompressedPubKey(compressed []byte) (string, error) {
	pub, err := secp256k1.ParsePubKey(compressed)
	if err != nil {
		return "", fmt.Errorf("parse pubkey: %w", err)
	}

	// Uncompressed is 65 bytes: 0x04 || X(32) || Y(32). Ethereum hashes the
	// 64-byte X||Y, dropping the 0x04 prefix.
	uncompressed := pub.SerializeUncompressed()
	if len(uncompressed) != 65 {
		return "", fmt.Errorf("unexpected uncompressed pubkey length %d", len(uncompressed))
	}

	h := sha3.NewLegacyKeccak256()
	h.Write(uncompressed[1:])
	digest := h.Sum(nil)

	addr := digest[12:] // last 20 bytes
	return toEIP55(addr), nil
}

// toEIP55 returns the mixed-case checksummed hex address (with 0x prefix) for a
// 20-byte address, per EIP-55: a hex digit is uppercased when the corresponding
// nibble of Keccak-256(lowercase-hex-address-without-0x) is >= 8.
func toEIP55(addr20 []byte) string {
	lower := hex.EncodeToString(addr20) // 40 lowercase hex chars, no 0x

	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(lower))
	hash := h.Sum(nil)

	out := make([]byte, 0, 42)
	out = append(out, '0', 'x')
	for i := 0; i < len(lower); i++ {
		c := lower[i]
		if c >= 'a' && c <= 'f' {
			// nibble i of the hash: high nibble for even i, low for odd.
			hashNibble := hash[i/2]
			if i%2 == 0 {
				hashNibble >>= 4
			} else {
				hashNibble &= 0x0f
			}
			if hashNibble >= 8 {
				c -= 32 // to uppercase
			}
		}
		out = append(out, c)
	}
	return string(out)
}
