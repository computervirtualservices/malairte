package primitives

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"

	"github.com/computervirtualservices/malairte/internal/crypto"
)

// WitnessScaleFactor is the multiplier applied to non-witness bytes when
// computing block weight. Pre-SegWit (no witness data) every byte simply counts
// WitnessScaleFactor times, so weight is just a scaled byte count. The
// constant is preserved so that SegWit integration only changes Weight()
// internals, not consensus constants derived from it.
const WitnessScaleFactor = 4

// BlockHeader is the structure that gets hashed for PoW.
// Serialized size: 4+32+32+8+4+8+8 = 96 bytes.
type BlockHeader struct {
	Version      uint32   // 4 bytes: block version
	PreviousHash [32]byte // 32 bytes: hash of previous block header
	MerkleRoot   [32]byte // 32 bytes: double-SHA3-256 merkle root of txids
	Timestamp    int64    // 8 bytes: Unix seconds
	Bits         uint32   // 4 bytes: compact difficulty target
	Nonce        uint64   // 8 bytes: mining nonce (uint64 for extended range)
	Height       uint64   // 8 bytes: block height
}

// Serialize encodes the header to exactly 96 bytes for hashing.
// Uses little-endian encoding for all numeric fields.
func (h *BlockHeader) Serialize() []byte {
	buf := make([]byte, 96)
	pos := 0

	binary.LittleEndian.PutUint32(buf[pos:], h.Version)
	pos += 4
	copy(buf[pos:], h.PreviousHash[:])
	pos += 32
	copy(buf[pos:], h.MerkleRoot[:])
	pos += 32
	binary.LittleEndian.PutUint64(buf[pos:], uint64(h.Timestamp))
	pos += 8
	binary.LittleEndian.PutUint32(buf[pos:], h.Bits)
	pos += 4
	binary.LittleEndian.PutUint64(buf[pos:], h.Nonce)
	pos += 8
	binary.LittleEndian.PutUint64(buf[pos:], h.Height)
	_ = pos // pos == 96

	return buf
}

// DeserializeBlockHeader decodes a 96-byte block header.
func DeserializeBlockHeader(data []byte) (*BlockHeader, error) {
	if len(data) < 96 {
		return nil, errTooShort
	}
	h := &BlockHeader{}
	pos := 0

	h.Version = binary.LittleEndian.Uint32(data[pos:])
	pos += 4
	copy(h.PreviousHash[:], data[pos:pos+32])
	pos += 32
	copy(h.MerkleRoot[:], data[pos:pos+32])
	pos += 32
	h.Timestamp = int64(binary.LittleEndian.Uint64(data[pos:]))
	pos += 8
	h.Bits = binary.LittleEndian.Uint32(data[pos:])
	pos += 4
	h.Nonce = binary.LittleEndian.Uint64(data[pos:])
	pos += 8
	h.Height = binary.LittleEndian.Uint64(data[pos:])

	return h, nil
}

// Hash returns DoubleSHA3256(h.Serialize()) — the MLRTHash of this header.
func (h *BlockHeader) Hash() [32]byte {
	return crypto.DoubleSHA3256(h.Serialize())
}

// Block contains a header and a slice of transactions.
type Block struct {
	Header BlockHeader
	Txs    []*Transaction
}

// Serialize encodes the block as: header bytes + varint(txCount) + each serialized tx.
func (b *Block) Serialize() []byte {
	var buf bytes.Buffer
	buf.Write(b.Header.Serialize())
	buf.Write(SerializeTransactions(b.Txs))
	return buf.Bytes()
}

// BaseSize is the block's non-witness serialized length: the 96-byte header
// plus the tx-count varint plus every transaction's SerializeBase length.
// Under the BIP-141 weight discount this is what contributes WitnessScaleFactor
// WU per byte.
func (b *Block) BaseSize() int {
	size := 96 // header
	size += len(encodeVarInt(uint64(len(b.Txs))))
	for _, tx := range b.Txs {
		size += tx.BaseSize()
	}
	return size
}

// TotalSize is the length of the full on-wire Serialize() output — header,
// tx-count varint, and every transaction serialized in SegWit format.
func (b *Block) TotalSize() int {
	return len(b.Serialize())
}

// Weight returns the block's consensus weight in weight units (WU) per BIP-141:
//   weight = baseSize*WitnessScaleFactor + (totalSize - baseSize)
// Every byte of witness data contributes 1 WU; every other byte contributes
// WitnessScaleFactor (=4) WU.
func (b *Block) Weight() int {
	base := b.BaseSize()
	total := b.TotalSize()
	return base*WitnessScaleFactor + (total - base)
}

// DeserializeBlock decodes a block from bytes.
func DeserializeBlock(data []byte) (*Block, error) {
	if len(data) < 96 {
		return nil, errTooShort
	}
	header, err := DeserializeBlockHeader(data[:96])
	if err != nil {
		return nil, err
	}
	txs, err := DeserializeTransactions(data[96:])
	if err != nil {
		return nil, err
	}
	return &Block{Header: *header, Txs: txs}, nil
}

// BlockHash is a [32]byte with hex string methods.
type BlockHash [32]byte

// String returns the block hash as a lowercase hex string.
func (bh BlockHash) String() string {
	return hex.EncodeToString(bh[:])
}

// WitnessCommitmentMagic is the 4-byte BIP-141 marker that identifies the
// witness commitment OP_RETURN output inside a coinbase transaction. The
// commitment script is: OP_RETURN 0x24 <magic> <32-byte commitment>.
var WitnessCommitmentMagic = [4]byte{0xaa, 0x21, 0xa9, 0xed}

// WitnessReservedValue is the 32-byte scratch space committed into the witness
// commitment hash. BIP-141 places this in the coinbase input's witness stack;
// pre-SegWit we simply commit to all zeros and mine as if the field is empty.
// Once witness data lands this will be read from coinbase.Inputs[0].Witness.
var WitnessReservedValue = [32]byte{}

// CalcWitnessMerkleRoot computes the BIP-141 witness merkle root: the merkle
// tree of each transaction's WTxID, with the coinbase's WTxID forced to
// all-zeros so that the commitment can sit inside the coinbase itself.
func CalcWitnessMerkleRoot(txs []*Transaction) [32]byte {
	if len(txs) == 0 {
		return [32]byte{}
	}
	hashes := make([][32]byte, len(txs))
	for i, tx := range txs {
		hashes[i] = tx.WTxID()
	}
	for len(hashes) > 1 {
		if len(hashes)%2 != 0 {
			hashes = append(hashes, hashes[len(hashes)-1])
		}
		next := make([][32]byte, len(hashes)/2)
		for i := 0; i < len(hashes); i += 2 {
			combined := make([]byte, 64)
			copy(combined[:32], hashes[i][:])
			copy(combined[32:], hashes[i+1][:])
			next[i/2] = crypto.DoubleSHA3256(combined)
		}
		hashes = next
	}
	return hashes[0]
}

// ComputeWitnessCommitment returns the 32-byte BIP-141 witness commitment:
//   Hash256(witnessMerkleRoot || WitnessReservedValue)
// The coinbase must carry this value inside an OP_RETURN output that begins
// with WitnessCommitmentMagic. See BuildWitnessCommitmentScript.
func ComputeWitnessCommitment(txs []*Transaction) [32]byte {
	root := CalcWitnessMerkleRoot(txs)
	buf := make([]byte, 64)
	copy(buf[:32], root[:])
	copy(buf[32:], WitnessReservedValue[:])
	return crypto.DoubleSHA3256(buf)
}

// BuildWitnessCommitmentScript produces the 38-byte script that carries the
// witness commitment in a coinbase output:
//   OP_RETURN (0x6a)
//   PUSH36    (0x24)
//   magic     (0xaa21a9ed)
//   commitment (32 bytes)
func BuildWitnessCommitmentScript(commitment [32]byte) []byte {
	out := make([]byte, 0, 38)
	out = append(out, 0x6a)                           // OP_RETURN
	out = append(out, 0x24)                           // push 36 bytes
	out = append(out, WitnessCommitmentMagic[:]...)   // 4-byte magic
	out = append(out, commitment[:]...)               // 32-byte commitment
	return out
}

// ExtractWitnessCommitment scans a coinbase transaction's outputs for the
// BIP-141 commitment and returns the last one found (multiple are allowed; the
// last wins). ok=false if no commitment is present.
func ExtractWitnessCommitment(coinbase *Transaction) (commitment [32]byte, ok bool) {
	if coinbase == nil {
		return [32]byte{}, false
	}
	for _, out := range coinbase.Outputs {
		s := out.ScriptPubKey
		if len(s) < 38 || s[0] != 0x6a || s[1] != 0x24 {
			continue
		}
		if s[2] != WitnessCommitmentMagic[0] ||
			s[3] != WitnessCommitmentMagic[1] ||
			s[4] != WitnessCommitmentMagic[2] ||
			s[5] != WitnessCommitmentMagic[3] {
			continue
		}
		copy(commitment[:], s[6:38])
		ok = true // keep scanning — last commitment wins
	}
	return commitment, ok
}

// CalcMerkleRoot computes the merkle root of a slice of transactions using their TxIDs.
// Uses DoubleSHA3256 for intermediate node hashing. If there are no transactions,
// it returns an all-zeros hash.
func CalcMerkleRoot(txs []*Transaction) [32]byte {
	if len(txs) == 0 {
		return [32]byte{}
	}

	// Build leaf level from TxIDs
	hashes := make([][32]byte, len(txs))
	for i, tx := range txs {
		hashes[i] = tx.TxID()
	}

	// Iteratively compute the merkle tree
	for len(hashes) > 1 {
		// Duplicate last element if odd count (Bitcoin-style)
		if len(hashes)%2 != 0 {
			hashes = append(hashes, hashes[len(hashes)-1])
		}
		next := make([][32]byte, len(hashes)/2)
		for i := 0; i < len(hashes); i += 2 {
			combined := make([]byte, 64)
			copy(combined[:32], hashes[i][:])
			copy(combined[32:], hashes[i+1][:])
			next[i/2] = crypto.DoubleSHA3256(combined)
		}
		hashes = next
	}

	return hashes[0]
}

// NewCoinbaseTx creates a valid coinbase transaction with the given parameters.
// The coinbase scriptSig encodes: block height (BIP34-style) + extraNonce + optional data.
// height: block height being mined.
// reward: block subsidy in atoms.
// scriptPubKey: output locking script (P2PKH for miner's address).
// extraNonce: additional nonce to vary the coinbase hash.
func NewCoinbaseTx(height uint64, reward int64, scriptPubKey []byte, extraNonce uint64) *Transaction {
	// Build coinbase scriptSig: BIP34-style height push + extraNonce + genesis message
	coinbaseMsg := []byte("MLRT Genesis - The Malairt coin begins.")
	if height > 0 {
		coinbaseMsg = []byte{}
	}

	// BIP34: encode block height as minimal push
	heightScript := encodeScriptHeight(height)

	// ExtraNonce as 8 bytes LE
	extraNonceBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(extraNonceBytes, extraNonce)

	scriptSig := make([]byte, 0, len(heightScript)+8+len(coinbaseMsg))
	scriptSig = append(scriptSig, heightScript...)
	scriptSig = append(scriptSig, extraNonceBytes...)
	scriptSig = append(scriptSig, coinbaseMsg...)

	tx := &Transaction{
		Version: 1,
		Inputs: []TxInput{
			{
				PreviousOutput: OutPoint{
					TxID:  [32]byte{}, // all zeros for coinbase
					Index: 0xFFFFFFFF,
				},
				ScriptSig: scriptSig,
				Sequence:  0xFFFFFFFF,
			},
		},
		Outputs: []TxOutput{
			{
				Value:        reward,
				ScriptPubKey: scriptPubKey,
			},
		},
		LockTime: 0,
	}
	return tx
}

// encodeScriptHeight encodes a block height in BIP34 script format.
// This is a minimal push of the height as a little-endian signed integer.
func encodeScriptHeight(height uint64) []byte {
	if height == 0 {
		return []byte{0x01, 0x00} // OP_PUSHDATA1 0x00
	}

	// Encode as minimal little-endian bytes
	var heightBytes []byte
	for height > 0 {
		heightBytes = append(heightBytes, byte(height&0xFF))
		height >>= 8
	}
	// Ensure positive sign bit
	if heightBytes[len(heightBytes)-1]&0x80 != 0 {
		heightBytes = append(heightBytes, 0x00)
	}

	result := make([]byte, 1+len(heightBytes))
	result[0] = byte(len(heightBytes))
	copy(result[1:], heightBytes)
	return result
}
