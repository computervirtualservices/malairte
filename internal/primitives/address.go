// Package primitives contains the core blockchain data structures for Malairt.
package primitives

// Bitcoin script opcodes used in P2PKH scripts.
const (
	OpDup         = 0x76 // OP_DUP
	OpHash160     = 0xa9 // OP_HASH160
	OpEqualVerify = 0x88 // OP_EQUALVERIFY
	OpCheckSig    = 0xac // OP_CHECKSIG
	OpData20      = 0x14 // Push 20 bytes
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
