// Package network implements the Malairt P2P wire protocol.
package network

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/computervirtualservices/malairte/internal/crypto"
	"github.com/computervirtualservices/malairte/internal/primitives"
)

// Message command strings (12 bytes max, null-padded on the wire).
const (
	CmdVersion   = "version"
	CmdVerAck    = "verack"
	CmdPing      = "ping"
	CmdPong      = "pong"
	CmdInv       = "inv"
	CmdGetData   = "getdata"
	CmdBlock     = "block"
	CmdTx        = "tx"
	CmdGetBlocks = "getblocks"
	CmdHeaders   = "headers"
)

// Inventory object types.
const (
	InvTypeTx    uint32 = 1
	InvTypeBlock uint32 = 2
)

// NetMessage is the decoded wire frame for a P2P message.
type NetMessage struct {
	// Magic is the 4-byte network identifier.
	Magic [4]byte
	// Command is the human-readable message type.
	Command string
	// Payload is the raw message payload bytes.
	Payload []byte
}

// EncodeMessage frames a payload into a complete NetMessage wire frame.
// Wire format:
//
//	[4]byte  magic
//	[12]byte command (null-padded ASCII)
//	uint32   payload length (little-endian)
//	[4]byte  checksum (first 4 bytes of SHA3-256(payload))
//	[]byte   payload
func EncodeMessage(magic [4]byte, command string, payload []byte) []byte {
	var buf bytes.Buffer

	// Magic (4 bytes)
	buf.Write(magic[:])

	// Command (12 bytes, null-padded)
	var cmdBytes [12]byte
	copy(cmdBytes[:], []byte(command))
	buf.Write(cmdBytes[:])

	// Payload length (4 bytes LE)
	var lenBytes [4]byte
	binary.LittleEndian.PutUint32(lenBytes[:], uint32(len(payload)))
	buf.Write(lenBytes[:])

	// Checksum: first 4 bytes of SHA3-256(payload)
	checksum := messageChecksum(payload)
	buf.Write(checksum[:])

	// Payload
	buf.Write(payload)

	return buf.Bytes()
}

// DecodeMessage reads and validates one complete NetMessage from a reader.
// Returns an error if the magic bytes don't match or the checksum is invalid.
func DecodeMessage(r io.Reader, magic [4]byte) (*NetMessage, error) {
	// Read header: 4 (magic) + 12 (command) + 4 (length) + 4 (checksum) = 24 bytes
	header := make([]byte, 24)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("read message header: %w", err)
	}

	// Validate magic
	var gotMagic [4]byte
	copy(gotMagic[:], header[:4])
	if gotMagic != magic {
		return nil, fmt.Errorf("magic mismatch: expected %x, got %x", magic, gotMagic)
	}

	// Parse command (12 bytes, null-padded)
	cmdRaw := header[4:16]
	cmdEnd := bytes.IndexByte(cmdRaw, 0)
	if cmdEnd < 0 {
		cmdEnd = 12
	}
	command := string(cmdRaw[:cmdEnd])

	// Parse payload length
	payloadLen := binary.LittleEndian.Uint32(header[16:20])

	// Sanity-check payload length (max 32 MB)
	const maxPayload = 32 * 1024 * 1024
	if payloadLen > maxPayload {
		return nil, fmt.Errorf("payload length %d exceeds maximum %d", payloadLen, maxPayload)
	}

	// Parse expected checksum
	var expectedChecksum [4]byte
	copy(expectedChecksum[:], header[20:24])

	// Read payload
	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, fmt.Errorf("read payload: %w", err)
		}
	}

	// Verify checksum
	actualChecksum := messageChecksum(payload)
	if actualChecksum != expectedChecksum {
		return nil, errors.New("message checksum mismatch")
	}

	return &NetMessage{
		Magic:   gotMagic,
		Command: command,
		Payload: payload,
	}, nil
}

// messageChecksum returns the first 4 bytes of SHA3-256(payload).
func messageChecksum(payload []byte) [4]byte {
	hash := crypto.SHA3256(payload)
	var cs [4]byte
	copy(cs[:], hash[:4])
	return cs
}

// --- Message type structs ---

// VersionMsg is sent when a peer first connects to announce its capabilities.
type VersionMsg struct {
	Version     uint32
	Services    uint64
	Timestamp   int64
	AddrRecv    string // host:port of the receiving peer
	AddrFrom    string // host:port of the sending peer
	Nonce       uint64
	UserAgent   string
	StartHeight int32
}

// Encode serializes the VersionMsg to bytes for transmission.
func (m *VersionMsg) Encode() []byte {
	var buf bytes.Buffer
	var tmp [8]byte

	binary.LittleEndian.PutUint32(tmp[:4], m.Version)
	buf.Write(tmp[:4])
	binary.LittleEndian.PutUint64(tmp[:], m.Services)
	buf.Write(tmp[:])
	binary.LittleEndian.PutUint64(tmp[:], uint64(m.Timestamp))
	buf.Write(tmp[:])
	writeVarString(&buf, m.AddrRecv)
	writeVarString(&buf, m.AddrFrom)
	binary.LittleEndian.PutUint64(tmp[:], m.Nonce)
	buf.Write(tmp[:])
	writeVarString(&buf, m.UserAgent)
	binary.LittleEndian.PutUint32(tmp[:4], uint32(m.StartHeight))
	buf.Write(tmp[:4])

	return buf.Bytes()
}

// DecodeVersionMsg deserializes a VersionMsg from bytes.
func DecodeVersionMsg(data []byte) (*VersionMsg, error) {
	if len(data) < 4+8+8 {
		return nil, errors.New("version msg too short")
	}
	m := &VersionMsg{}
	pos := 0

	m.Version = binary.LittleEndian.Uint32(data[pos:])
	pos += 4
	m.Services = binary.LittleEndian.Uint64(data[pos:])
	pos += 8
	m.Timestamp = int64(binary.LittleEndian.Uint64(data[pos:]))
	pos += 8

	var n int
	var err error
	m.AddrRecv, n, err = readVarString(data[pos:])
	if err != nil {
		return nil, err
	}
	pos += n

	m.AddrFrom, n, err = readVarString(data[pos:])
	if err != nil {
		return nil, err
	}
	pos += n

	if pos+8 > len(data) {
		return nil, errors.New("version msg truncated at nonce")
	}
	m.Nonce = binary.LittleEndian.Uint64(data[pos:])
	pos += 8

	m.UserAgent, n, err = readVarString(data[pos:])
	if err != nil {
		return nil, err
	}
	pos += n

	if pos+4 > len(data) {
		return nil, errors.New("version msg truncated at start height")
	}
	m.StartHeight = int32(binary.LittleEndian.Uint32(data[pos:]))

	return m, nil
}

// VerAckMsg has no payload — it simply acknowledges a version message.
type VerAckMsg struct{}

// Encode returns an empty byte slice.
func (m *VerAckMsg) Encode() []byte { return []byte{} }

// PingMsg requests an immediate response (pong).
type PingMsg struct {
	Nonce uint64
}

// Encode serializes the PingMsg.
func (m *PingMsg) Encode() []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, m.Nonce)
	return b
}

// DecodePingMsg deserializes a PingMsg.
func DecodePingMsg(data []byte) (*PingMsg, error) {
	if len(data) < 8 {
		return nil, errors.New("ping msg too short")
	}
	return &PingMsg{Nonce: binary.LittleEndian.Uint64(data[:8])}, nil
}

// PongMsg is the response to a ping.
type PongMsg struct {
	Nonce uint64
}

// Encode serializes the PongMsg.
func (m *PongMsg) Encode() []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, m.Nonce)
	return b
}

// DecodePongMsg deserializes a PongMsg.
func DecodePongMsg(data []byte) (*PongMsg, error) {
	if len(data) < 8 {
		return nil, errors.New("pong msg too short")
	}
	return &PongMsg{Nonce: binary.LittleEndian.Uint64(data[:8])}, nil
}

// InvVect is a single inventory item (type + hash).
type InvVect struct {
	Type uint32
	Hash [32]byte
}

// InvMsg announces one or more inventory items (transactions or blocks).
type InvMsg struct {
	Items []InvVect
}

// Encode serializes the InvMsg.
func (m *InvMsg) Encode() []byte {
	var buf bytes.Buffer
	buf.Write(primitives.EncodeVarIntPub(uint64(len(m.Items))))
	for _, item := range m.Items {
		var tmp [4]byte
		binary.LittleEndian.PutUint32(tmp[:], item.Type)
		buf.Write(tmp[:])
		buf.Write(item.Hash[:])
	}
	return buf.Bytes()
}

// DecodeInvMsg deserializes an InvMsg.
func DecodeInvMsg(data []byte) (*InvMsg, error) {
	count, n, err := primitives.DecodeVarInt(data)
	if err != nil {
		return nil, err
	}
	pos := n
	items := make([]InvVect, count)
	for i := uint64(0); i < count; i++ {
		if pos+36 > len(data) {
			return nil, errors.New("inv msg truncated")
		}
		items[i].Type = binary.LittleEndian.Uint32(data[pos:])
		pos += 4
		copy(items[i].Hash[:], data[pos:pos+32])
		pos += 32
	}
	return &InvMsg{Items: items}, nil
}

// GetDataMsg requests specific data items by inventory vector (same structure as InvMsg).
type GetDataMsg = InvMsg

// BlockMsg carries a full serialized block.
type BlockMsg struct {
	Block *primitives.Block
}

// Encode serializes the BlockMsg.
func (m *BlockMsg) Encode() []byte {
	return m.Block.Serialize()
}

// DecodeBlockMsg deserializes a BlockMsg.
func DecodeBlockMsg(data []byte) (*BlockMsg, error) {
	block, err := primitives.DeserializeBlock(data)
	if err != nil {
		return nil, err
	}
	return &BlockMsg{Block: block}, nil
}

// TxMsg carries a single serialized transaction.
type TxMsg struct {
	Tx *primitives.Transaction
}

// Encode serializes the TxMsg.
func (m *TxMsg) Encode() []byte {
	return m.Tx.Serialize()
}

// DecodeTxMsg deserializes a TxMsg.
func DecodeTxMsg(data []byte) (*TxMsg, error) {
	tx, _, err := primitives.DeserializeTx(data)
	if err != nil {
		return nil, err
	}
	return &TxMsg{Tx: tx}, nil
}

// GetBlocksMsg requests an inventory of blocks from a peer.
// The peer responds with an InvMsg containing block hashes.
type GetBlocksMsg struct {
	// BlockLocator is an ordered list of known block hashes
	// (from tip back to genesis) to help peers find the fork point.
	BlockLocator [][32]byte
	// StopHash indicates where the peer should stop sending; all-zeros means "send as many as possible".
	StopHash [32]byte
}

// Encode serializes the GetBlocksMsg.
func (m *GetBlocksMsg) Encode() []byte {
	var buf bytes.Buffer
	buf.Write(primitives.EncodeVarIntPub(uint64(len(m.BlockLocator))))
	for _, h := range m.BlockLocator {
		buf.Write(h[:])
	}
	buf.Write(m.StopHash[:])
	return buf.Bytes()
}

// DecodeGetBlocksMsg deserializes a GetBlocksMsg.
func DecodeGetBlocksMsg(data []byte) (*GetBlocksMsg, error) {
	count, n, err := primitives.DecodeVarInt(data)
	if err != nil {
		return nil, err
	}
	pos := n
	locator := make([][32]byte, count)
	for i := uint64(0); i < count; i++ {
		if pos+32 > len(data) {
			return nil, errors.New("getblocks msg truncated")
		}
		copy(locator[i][:], data[pos:pos+32])
		pos += 32
	}
	if pos+32 > len(data) {
		return nil, errors.New("getblocks msg missing stop hash")
	}
	var stopHash [32]byte
	copy(stopHash[:], data[pos:pos+32])
	return &GetBlocksMsg{BlockLocator: locator, StopHash: stopHash}, nil
}

// HeadersMsg carries a list of block headers (without transactions).
type HeadersMsg struct {
	Headers []primitives.BlockHeader
}

// Encode serializes the HeadersMsg.
func (m *HeadersMsg) Encode() []byte {
	var buf bytes.Buffer
	buf.Write(primitives.EncodeVarIntPub(uint64(len(m.Headers))))
	for _, h := range m.Headers {
		buf.Write(h.Serialize())
		// Bitcoin-style: each header in a headers message is followed by a varint tx count (always 0)
		buf.WriteByte(0x00)
	}
	return buf.Bytes()
}

// DecodeHeadersMsg deserializes a HeadersMsg.
func DecodeHeadersMsg(data []byte) (*HeadersMsg, error) {
	count, n, err := primitives.DecodeVarInt(data)
	if err != nil {
		return nil, err
	}
	pos := n
	headers := make([]primitives.BlockHeader, 0, count)
	for i := uint64(0); i < count; i++ {
		if pos+96 > len(data) {
			return nil, errors.New("headers msg truncated")
		}
		h, err := primitives.DeserializeBlockHeader(data[pos : pos+96])
		if err != nil {
			return nil, err
		}
		headers = append(headers, *h)
		pos += 96
		// Skip the tx count varint (always 0 in headers messages)
		if pos < len(data) {
			_, skip, err := primitives.DecodeVarInt(data[pos:])
			if err != nil {
				return nil, err
			}
			pos += skip
		}
	}
	return &HeadersMsg{Headers: headers}, nil
}

// writeVarString writes a length-prefixed string using Bitcoin varint encoding.
func writeVarString(buf *bytes.Buffer, s string) {
	buf.Write(primitives.EncodeVarIntPub(uint64(len(s))))
	buf.WriteString(s)
}

// readVarString reads a length-prefixed string using Bitcoin varint encoding.
func readVarString(data []byte) (string, int, error) {
	l, n, err := primitives.DecodeVarInt(data)
	if err != nil {
		return "", 0, err
	}
	if uint64(n)+l > uint64(len(data)) {
		return "", 0, errors.New("var string exceeds data length")
	}
	return string(data[n : n+int(l)]), n + int(l), nil
}
