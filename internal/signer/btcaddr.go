package signer

import (
	"errors"
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
//	program = HASH160(compressedPubKey)              (20 bytes)
//	address = bech32(hrp, [witnessVersion=0] ++ convertbits(program, 8->5))
//
// Witness v0 uses bech32 (not bech32m); the node's crypto.EncodeBech32 is the
// BIP173 codec (polymod ^ 1), which is correct for v0. HRP is "bc" for mainnet,
// "tb" for testnet. Correctness is pinned to the BIP173 reference vector in the
// package test.
func btcP2WPKHFromCompressedPubKey(compressed []byte, hrp string) (string, error) {
	if len(compressed) != 33 {
		return "", fmt.Errorf("expected 33-byte compressed pubkey, got %d", len(compressed))
	}

	h160 := crypto.Hash160(compressed) // [20]byte

	converted, err := convertBits(h160[:], 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("convertbits: %w", err)
	}

	// Prepend the witness version (0) as a single 5-bit value.
	data := make([]byte, 0, 1+len(converted))
	data = append(data, 0x00)
	data = append(data, converted...)

	addr, err := crypto.EncodeBech32(hrp, data)
	if err != nil {
		return "", fmt.Errorf("encode bech32: %w", err)
	}
	return addr, nil
}

// convertBits regroups a byte slice from `fromBits`-wide groups to
// `toBits`-wide groups (the BIP173 helper). With pad=true any remaining bits are
// left-padded with zeroes into a final group.
func convertBits(data []byte, fromBits, toBits uint, pad bool) ([]byte, error) {
	var acc uint32
	var bits uint
	var out []byte
	maxv := uint32((1 << toBits) - 1)
	maxAcc := uint32((1 << (fromBits + toBits - 1)) - 1)

	for _, b := range data {
		v := uint32(b)
		if (v >> fromBits) != 0 {
			return nil, fmt.Errorf("input value %d exceeds %d bits", v, fromBits)
		}
		acc = ((acc << fromBits) | v) & maxAcc
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			out = append(out, byte((acc>>bits)&maxv))
		}
	}

	if pad {
		if bits > 0 {
			out = append(out, byte((acc<<(toBits-bits))&maxv))
		}
	} else if bits >= fromBits || ((acc<<(toBits-bits))&maxv) != 0 {
		return nil, errors.New("invalid padding in convertbits")
	}

	return out, nil
}
