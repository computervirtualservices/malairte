package primitives

import (
	"bytes"
	"testing"
)

func TestP2PKHScript(t *testing.T) {
	var hash [20]byte
	for i := range hash {
		hash[i] = byte(i + 1)
	}

	script := P2PKHScript(hash)

	if len(script) != 25 {
		t.Errorf("P2PKHScript length: expected 25, got %d", len(script))
	}
	if script[0] != OpDup {
		t.Errorf("script[0] should be OP_DUP (0x76), got 0x%02x", script[0])
	}
	if script[1] != OpHash160 {
		t.Errorf("script[1] should be OP_HASH160 (0xa9), got 0x%02x", script[1])
	}
	if script[2] != OpData20 {
		t.Errorf("script[2] should be 0x14 (push 20 bytes), got 0x%02x", script[2])
	}
	if !bytes.Equal(script[3:23], hash[:]) {
		t.Errorf("script[3:23] should contain the pubkey hash")
	}
	if script[23] != OpEqualVerify {
		t.Errorf("script[23] should be OP_EQUALVERIFY (0x88), got 0x%02x", script[23])
	}
	if script[24] != OpCheckSig {
		t.Errorf("script[24] should be OP_CHECKSIG (0xac), got 0x%02x", script[24])
	}
}

func TestIsP2PKHScript(t *testing.T) {
	var hash [20]byte
	script := P2PKHScript(hash)

	if !IsP2PKHScript(script) {
		t.Error("IsP2PKHScript should return true for a valid P2PKH script")
	}

	// Wrong length
	if IsP2PKHScript(script[:24]) {
		t.Error("IsP2PKHScript should return false for 24-byte script")
	}

	// Wrong first opcode
	bad := make([]byte, 25)
	copy(bad, script)
	bad[0] = 0x00
	if IsP2PKHScript(bad) {
		t.Error("IsP2PKHScript should return false when first opcode is wrong")
	}

	// Wrong last opcode
	bad2 := make([]byte, 25)
	copy(bad2, script)
	bad2[24] = 0x00
	if IsP2PKHScript(bad2) {
		t.Error("IsP2PKHScript should return false when last opcode is wrong")
	}
}

func TestExtractP2PKHHash(t *testing.T) {
	var hash [20]byte
	for i := range hash {
		hash[i] = byte(i * 5)
	}

	script := P2PKHScript(hash)
	extracted, ok := ExtractP2PKHHash(script)

	if !ok {
		t.Fatal("ExtractP2PKHHash should succeed for valid P2PKH script")
	}
	if extracted != hash {
		t.Errorf("Extracted hash mismatch: got %x, want %x", extracted, hash)
	}
}

func TestExtractP2PKHHashInvalid(t *testing.T) {
	_, ok := ExtractP2PKHHash([]byte{0x00, 0x01, 0x02})
	if ok {
		t.Error("ExtractP2PKHHash should fail for invalid script")
	}
}

func TestP2PKHScriptRoundTrip(t *testing.T) {
	var hash [20]byte
	hash[0] = 0xAB
	hash[19] = 0xCD

	script := P2PKHScript(hash)
	extracted, ok := ExtractP2PKHHash(script)

	if !ok {
		t.Fatal("round-trip extract failed")
	}
	if extracted != hash {
		t.Errorf("round-trip mismatch: got %x, want %x", extracted, hash)
	}
}
