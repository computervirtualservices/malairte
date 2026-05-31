package signer

import (
	"fmt"

	"github.com/computervirtualservices/malairte/internal/crypto"
)

// BTCAddressFromCompressedPubKey is the exported entry point used by
// signerd-keygen so the generator and the running signer agree byte-for-byte.
func BTCAddressFromCompressedPubKey(compressed []byte, hrp string) (string, error) {
	return btcP2WPKHFromCompressedPubKey(compressed, hrp)
}

// btcP2WPKHFromCompressedPubKey derives a native SegWit v0 P2WPKH Bitcoin
// address (bech32, "bc1q…") from a 33-byte compressed secp256k1 public key.
//
//	program = HASH160(compressedPubKey)   (20 bytes)
//	address = bech32(hrp, witnessVersion=0, program)
//
// It reuses the node's audited crypto.EncodeSegWitAddress, which handles the
// 8→5-bit regrouping and selects bech32 (not bech32m) for witness v0 per
// BIP173. HRP is "bc" mainnet, "tb" testnet. Pinned to the BIP173 reference
// vector in the package test.
func btcP2WPKHFromCompressedPubKey(compressed []byte, hrp string) (string, error) {
	if len(compressed) != 33 {
		return "", fmt.Errorf("expected 33-byte compressed pubkey, got %d", len(compressed))
	}

	h160 := crypto.Hash160(compressed) // [20]byte

	addr, err := crypto.EncodeSegWitAddress(hrp, 0, h160[:])
	if err != nil {
		return "", fmt.Errorf("encode segwit address: %w", err)
	}
	return addr, nil
}
