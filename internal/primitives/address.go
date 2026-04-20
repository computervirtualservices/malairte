// Package primitives contains the core blockchain data structures for Malairt.
package primitives

// Bitcoin script opcodes used in standard output templates.
const (
	OpDup         = 0x76 // OP_DUP
	OpHash160     = 0xa9 // OP_HASH160
	OpEqualVerify = 0x88 // OP_EQUALVERIFY
	OpCheckSig    = 0xac // OP_CHECKSIG
	OpData20      = 0x14 // Push 20 bytes
	OpData32      = 0x20 // Push 32 bytes
	Op0           = 0x00 // OP_0 (witness v0 marker)
	Op1           = 0x51 // OP_1 (witness v1 marker — taproot)
)

// P2PKHScript creates an output script for Pay-To-Public-Key-Hash:
// OP_DUP OP_HASH160 <pubKeyHash20> OP_EQUALVERIFY OP_CHECKSIG.
func P2PKHScript(pubKeyHash [20]byte) []byte {
	script := make([]byte, 25)
	script[0] = OpDup
	script[1] = OpHash160
	script[2] = OpData20
	copy(script[3:23], pubKeyHash[:])
	script[23] = OpEqualVerify
	script[24] = OpCheckSig
	return script
}

// ExtractP2PKHHash extracts the 20-byte pubkey hash from a P2PKH output script.
// Returns (hash, true) on success, ([20]byte{}, false) on failure.
func ExtractP2PKHHash(script []byte) ([20]byte, bool) {
	if !IsP2PKHScript(script) {
		return [20]byte{}, false
	}
	var hash [20]byte
	copy(hash[:], script[3:23])
	return hash, true
}

// IsP2PKHScript returns true if script is a standard P2PKH script.
// A valid P2PKH script is exactly 25 bytes: OP_DUP OP_HASH160 0x14 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG.
func IsP2PKHScript(script []byte) bool {
	return len(script) == 25 &&
		script[0] == OpDup &&
		script[1] == OpHash160 &&
		script[2] == OpData20 &&
		script[23] == OpEqualVerify &&
		script[24] == OpCheckSig
}

// P2WPKHScript creates an output script for native SegWit v0 Pay-to-Witness-
// Public-Key-Hash: OP_0 (0x00) <push 20> <pubKeyHash20>. Total 22 bytes.
// The spend must carry [signature, pubkey] in the input's witness stack.
func P2WPKHScript(pubKeyHash [20]byte) []byte {
	script := make([]byte, 22)
	script[0] = 0x00 // OP_0 (witness version)
	script[1] = OpData20
	copy(script[2:22], pubKeyHash[:])
	return script
}

// IsP2WPKHScript returns true if script is a native SegWit v0 P2WPKH script:
// exactly 22 bytes, starting OP_0 0x14 ... (BIP-141 witness-v0 program).
func IsP2WPKHScript(script []byte) bool {
	return len(script) == 22 && script[0] == 0x00 && script[1] == OpData20
}

// ExtractP2WPKHHash extracts the 20-byte pubkey hash from a P2WPKH output.
func ExtractP2WPKHHash(script []byte) ([20]byte, bool) {
	if !IsP2WPKHScript(script) {
		return [20]byte{}, false
	}
	var hash [20]byte
	copy(hash[:], script[2:22])
	return hash, true
}

// P2TRScript creates a native SegWit v1 (taproot) output script:
//   OP_1 (0x51) OP_DATA_32 (0x20) <32-byte x-only tweaked pubkey>
// The 32 bytes are the BIP-341 tweaked output key — the x coordinate of the
// point Q = P + tagged_hash("TapTweak", P || merkleRoot) * G. Callers that
// do not use tapscript pass merkleRoot = nil, which degenerates Q = P + t*G
// for t = tagged_hash("TapTweak", P).
func P2TRScript(xonly [32]byte) []byte {
	script := make([]byte, 34)
	script[0] = Op1
	script[1] = OpData32
	copy(script[2:34], xonly[:])
	return script
}

// IsP2TRScript returns true if script is a standard P2TR output:
// exactly 34 bytes beginning OP_1 0x20.
func IsP2TRScript(script []byte) bool {
	return len(script) == 34 && script[0] == Op1 && script[1] == OpData32
}

// ExtractP2TRKey returns the 32-byte x-only tweaked output key from a P2TR
// output script.
func ExtractP2TRKey(script []byte) ([32]byte, bool) {
	if !IsP2TRScript(script) {
		return [32]byte{}, false
	}
	var key [32]byte
	copy(key[:], script[2:34])
	return key, true
}
