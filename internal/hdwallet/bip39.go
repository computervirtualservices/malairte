// Package hdwallet provides OFFLINE BIP39 (mnemonic) + BIP32 (HD key)
// generation for the CoinDock signer. It is used by cmd/signerd-keygen to
// produce an account xpub (MLRT_ACCOUNT_XPUB) from a freshly generated seed.
//
// It deliberately reuses the node's own crypto package (secp256k1, Hash160,
// Base58Check) so the keys/addresses it produces match what the node and the
// signer use byte-for-byte. Correctness is pinned to the canonical BIP39/BIP32
// specification test vectors in the package tests.
//
// SECURITY: the mnemonic and any private extended key produced here are secret.
// Generate them on an offline machine; never commit or transmit them.
package hdwallet

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

//go:embed english.txt
var englishWordlistRaw string

var (
	wordlist  []string
	wordIndex map[string]int
)

func init() {
	wordlist = strings.Fields(englishWordlistRaw)
	if len(wordlist) != 2048 {
		panic(fmt.Sprintf("bip39: expected 2048 words, got %d", len(wordlist)))
	}
	wordIndex = make(map[string]int, 2048)
	for i, w := range wordlist {
		wordIndex[w] = i
	}
}

// NewEntropy returns cryptographically random entropy of bits length
// (128, 160, 192, 224, or 256).
func NewEntropy(bits int) ([]byte, error) {
	if err := validateEntropyBits(bits); err != nil {
		return nil, err
	}
	b := make([]byte, bits/8)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("read entropy: %w", err)
	}
	return b, nil
}

// EntropyToMnemonic converts entropy to a BIP39 mnemonic sentence.
func EntropyToMnemonic(entropy []byte) (string, error) {
	bits := len(entropy) * 8
	if err := validateEntropyBits(bits); err != nil {
		return "", err
	}

	// Append a checksum: the first ENT/32 bits of SHA256(entropy).
	checksumBits := bits / 32
	hash := sha256.Sum256(entropy)

	// Build a big-endian bit string of entropy || checksum, then read it in
	// 11-bit groups, each indexing the wordlist.
	totalBits := bits + checksumBits
	getBit := func(data []byte, i int) int {
		return int((data[i/8] >> (7 - uint(i%8))) & 1)
	}

	words := make([]string, totalBits/11)
	for i := 0; i < totalBits/11; i++ {
		idx := 0
		for j := 0; j < 11; j++ {
			bitPos := i*11 + j
			var bit int
			if bitPos < bits {
				bit = getBit(entropy, bitPos)
			} else {
				bit = getBit(hash[:], bitPos-bits)
			}
			idx = (idx << 1) | bit
		}
		words[i] = wordlist[idx]
	}
	return strings.Join(words, " "), nil
}

// NewMnemonic generates fresh entropy and returns a mnemonic of the given bit
// strength (256 bits → 24 words is recommended).
func NewMnemonic(bits int) (string, error) {
	entropy, err := NewEntropy(bits)
	if err != nil {
		return "", err
	}
	return EntropyToMnemonic(entropy)
}

// ValidateMnemonic checks the word count, membership, and the BIP39 checksum.
func ValidateMnemonic(mnemonic string) bool {
	words := strings.Fields(strings.TrimSpace(mnemonic))
	switch len(words) {
	case 12, 15, 18, 21, 24:
	default:
		return false
	}

	// Reconstruct the entropy+checksum bitstream from word indices.
	totalBits := len(words) * 11
	bits := make([]byte, (totalBits+7)/8)
	pos := 0
	for _, w := range words {
		idx, ok := wordIndex[w]
		if !ok {
			return false
		}
		for j := 10; j >= 0; j-- {
			if (idx>>uint(j))&1 == 1 {
				bits[pos/8] |= 1 << (7 - uint(pos%8))
			}
			pos++
		}
	}

	entBits := totalBits / 33 * 32
	csBits := totalBits - entBits
	entropy := make([]byte, entBits/8)
	copy(entropy, bits[:entBits/8])

	hash := sha256.Sum256(entropy)
	for i := 0; i < csBits; i++ {
		want := (hash[i/8] >> (7 - uint(i%8))) & 1
		got := (bits[(entBits+i)/8] >> (7 - uint((entBits+i)%8))) & 1
		if want != got {
			return false
		}
	}
	return true
}

// MnemonicToSeed derives the 64-byte BIP39 seed from a mnemonic and optional
// passphrase (PBKDF2-HMAC-SHA512, 2048 iterations, salt "mnemonic"+passphrase).
func MnemonicToSeed(mnemonic, passphrase string) []byte {
	norm := strings.Join(strings.Fields(strings.TrimSpace(mnemonic)), " ")
	return pbkdf2.Key([]byte(norm), []byte("mnemonic"+passphrase), 2048, 64, sha512.New)
}

func validateEntropyBits(bits int) error {
	switch bits {
	case 128, 160, 192, 224, 256:
		return nil
	default:
		return errors.New("entropy must be 128, 160, 192, 224, or 256 bits")
	}
}

// hmacSHA512 is a small helper shared by the BIP32 code.
func hmacSHA512(key, data []byte) []byte {
	m := hmac.New(sha512.New, key)
	m.Write(data)
	return m.Sum(nil)
}
