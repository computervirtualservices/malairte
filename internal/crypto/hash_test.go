package crypto

import (
	"encoding/hex"
	"testing"
)

func TestSHA3256(t *testing.T) {
	// SHA3-256 of empty string: known value
	result := SHA3256([]byte{})
	// SHA3-256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
	expected := "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
	if hex.EncodeToString(result[:]) != expected {
		t.Errorf("SHA3256 of empty: got %x, want %s", result, expected)
	}
}

func TestDoubleSHA3256(t *testing.T) {
	data := []byte("Malairt")
	h1 := SHA3256(data)
	h2 := SHA3256(h1[:])
	result := DoubleSHA3256(data)
	if result != h2 {
		t.Errorf("DoubleSHA3256 mismatch: got %x, want %x", result, h2)
	}
}

func TestHash256Deterministic(t *testing.T) {
	data := []byte("hello world")
	h1 := Hash256(data)
	h2 := Hash256(data)
	if h1 != h2 {
		t.Errorf("Hash256 not deterministic: %x vs %x", h1, h2)
	}
}

func TestHash160Length(t *testing.T) {
	pubKey := []byte{0x02, 0x01, 0x02, 0x03}
	result := Hash160(pubKey)
	// Result should always be 20 bytes
	if len(result) != 20 {
		t.Errorf("Hash160 should return 20 bytes, got %d", len(result))
	}
}

func TestDoubleSHA3256NotSameAsSingle(t *testing.T) {
	data := []byte("test data")
	single := SHA3256(data)
	double := DoubleSHA3256(data)
	if single == double {
		t.Errorf("DoubleSHA3256 should differ from single SHA3256 for non-fixed-point inputs")
	}
}
