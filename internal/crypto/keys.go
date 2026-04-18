package crypto

import (
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// GenerateKeyPair generates a new random secp256k1 private/public key pair.
// Returns privKey bytes (32), compressed pubKey bytes (33), and any error.
func GenerateKeyPair() (privKey []byte, pubKey []byte, err error) {
	privKeyObj, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("generate private key: %w", err)
	}
	privKey = privKeyObj.Serialize()
	pubKey = privKeyObj.PubKey().SerializeCompressed()
	return privKey, pubKey, nil
}

// PubKeyFromPrivKey derives a compressed public key from private key bytes.
func PubKeyFromPrivKey(privKeyBytes []byte) ([]byte, error) {
	if len(privKeyBytes) != 32 {
		return nil, errors.New("private key must be 32 bytes")
	}
	privKey := secp256k1.PrivKeyFromBytes(privKeyBytes)
	return privKey.PubKey().SerializeCompressed(), nil
}

// Sign signs a 32-byte hash with the private key. Returns DER-encoded signature.
func Sign(privKeyBytes []byte, hash []byte) ([]byte, error) {
	if len(privKeyBytes) != 32 {
		return nil, errors.New("private key must be 32 bytes")
	}
	if len(hash) != 32 {
		return nil, errors.New("hash must be 32 bytes")
	}
	privKey := secp256k1.PrivKeyFromBytes(privKeyBytes)
	sig := ecdsa.Sign(privKey, hash)
	return sig.Serialize(), nil
}

// Verify verifies a DER-encoded signature against hash and compressed pubkey.
// Returns true if the signature is valid.
func Verify(pubKeyBytes []byte, hash []byte, sig []byte) bool {
	pubKey, err := secp256k1.ParsePubKey(pubKeyBytes)
	if err != nil {
		return false
	}
	parsedSig, err := ecdsa.ParseDERSignature(sig)
	if err != nil {
		return false
	}
	return parsedSig.Verify(hash, pubKey)
}

// PubKeyToAddress derives a Base58Check address from compressed public key bytes.
// versionByte: 50 for mainnet ("M"), 111 for testnet ("m").
func PubKeyToAddress(pubKeyBytes []byte, versionByte byte) (string, error) {
	if len(pubKeyBytes) == 0 {
		return "", errors.New("public key bytes cannot be empty")
	}
	pubKeyHash := Hash160(pubKeyBytes)
	return Base58CheckEncode(versionByte, pubKeyHash[:])
}

// Base58CheckEncode encodes version + payload as a Base58Check string.
func Base58CheckEncode(version byte, payload []byte) (string, error) {
	data := make([]byte, 1+len(payload))
	data[0] = version
	copy(data[1:], payload)
	checksum := Hash256(data)
	full := append(data, checksum[:4]...)
	return base58Encode(full), nil
}

// Base58CheckDecode decodes a Base58Check string, returning (version, payload, error).
func Base58CheckDecode(s string) (byte, []byte, error) {
	decoded := base58Decode(s)
	if len(decoded) < 5 {
		return 0, nil, errors.New("base58check: too short")
	}
	// Verify checksum
	payload := decoded[:len(decoded)-4]
	checksum := decoded[len(decoded)-4:]
	expected := Hash256(payload)
	for i := 0; i < 4; i++ {
		if checksum[i] != expected[i] {
			return 0, nil, errors.New("base58check: invalid checksum")
		}
	}
	return payload[0], payload[1:], nil
}

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// base58Encode encodes bytes to a Base58 string.
func base58Encode(input []byte) string {
	// Count leading zeros
	leadingZeros := 0
	for _, b := range input {
		if b != 0 {
			break
		}
		leadingZeros++
	}

	// Convert to big integer representation via repeated division
	num := make([]byte, len(input))
	copy(num, input)

	var result []byte
	for len(num) > 0 {
		remainder := 0
		var newNum []byte
		for _, b := range num {
			digit := remainder*256 + int(b)
			q := digit / 58
			remainder = digit % 58
			if len(newNum) > 0 || q > 0 {
				newNum = append(newNum, byte(q))
			}
		}
		result = append(result, base58Alphabet[remainder])
		num = newNum
	}

	// Add leading '1's for leading zero bytes
	for i := 0; i < leadingZeros; i++ {
		result = append(result, base58Alphabet[0])
	}

	// Reverse result
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return string(result)
}

// base58Decode decodes a Base58 string to bytes.
func base58Decode(s string) []byte {
	// Count leading '1's
	leadingZeros := 0
	for _, c := range s {
		if c != '1' {
			break
		}
		leadingZeros++
	}

	num := []byte{0}
	for _, c := range s {
		charIndex := -1
		for i, a := range base58Alphabet {
			if a == c {
				charIndex = i
				break
			}
		}
		if charIndex < 0 {
			return nil
		}
		// num = num * 58 + charIndex
		carry := charIndex
		for i := len(num) - 1; i >= 0; i-- {
			carry += 58 * int(num[i])
			num[i] = byte(carry % 256)
			carry /= 256
		}
		for carry > 0 {
			num = append([]byte{byte(carry % 256)}, num...)
			carry /= 256
		}
	}

	// Remove leading zeros added by algorithm
	i := 0
	for i < len(num) && num[i] == 0 {
		i++
	}

	result := make([]byte, leadingZeros+len(num)-i)
	copy(result[leadingZeros:], num[i:])
	return result
}

