package network_test

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/computervirtualservices/malairte/internal/network"
	"github.com/computervirtualservices/malairte/internal/primitives"
)

// testMagic is a magic value used throughout the message tests.
var testMagic = [4]byte{0x4D, 0x4C, 0x52, 0x54} // "MLRT"

// ── EncodeMessage / DecodeMessage ─────────────────────────────────────────────

func TestEncodeDecodeMessage_RoundTrip(t *testing.T) {
	payload := []byte("hello, world")
	encoded := network.EncodeMessage(testMagic, "ping", payload)

	msg, err := network.DecodeMessage(bytes.NewReader(encoded), testMagic)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}
	if msg.Command != "ping" {
		t.Errorf("Command: got %q, want ping", msg.Command)
	}
	if !bytes.Equal(msg.Payload, payload) {
		t.Errorf("Payload: got %x, want %x", msg.Payload, payload)
	}
}

func TestEncodeDecodeMessage_EmptyPayload(t *testing.T) {
	encoded := network.EncodeMessage(testMagic, "verack", []byte{})

	msg, err := network.DecodeMessage(bytes.NewReader(encoded), testMagic)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}
	if msg.Command != "verack" {
		t.Errorf("Command: got %q, want verack", msg.Command)
	}
	if len(msg.Payload) != 0 {
		t.Errorf("Payload should be empty, got %d bytes", len(msg.Payload))
	}
}

func TestDecodeMessage_MagicMismatch(t *testing.T) {
	wrongMagic := [4]byte{0xFF, 0xFF, 0xFF, 0xFF}
	encoded := network.EncodeMessage(testMagic, "ping", []byte("data"))
	_, err := network.DecodeMessage(bytes.NewReader(encoded), wrongMagic)
	if err == nil {
		t.Error("expected error for magic mismatch")
	}
}

func TestDecodeMessage_ChecksumMismatch(t *testing.T) {
	payload := []byte("payload data")
	encoded := network.EncodeMessage(testMagic, "ping", payload)
	// Corrupt the last byte of the payload.
	encoded[len(encoded)-1] ^= 0xFF
	_, err := network.DecodeMessage(bytes.NewReader(encoded), testMagic)
	if err == nil {
		t.Error("expected error for checksum mismatch")
	}
}

func TestDecodeMessage_PayloadTooBig(t *testing.T) {
	// Construct a raw header that claims a 33 MB payload (exceeds the 32 MB limit).
	header := make([]byte, 24)
	copy(header[:4], testMagic[:])
	copy(header[4:16], []byte("ping")) // command (null-padded)
	binary.LittleEndian.PutUint32(header[16:20], 33*1024*1024)
	// checksum stays zero — the size check fires before reading the payload.

	_, err := network.DecodeMessage(bytes.NewReader(header), testMagic)
	if err == nil {
		t.Error("expected error for oversized payload length")
	}
}

func TestDecodeMessage_TruncatedHeader(t *testing.T) {
	// Only 10 bytes: too short for even the 24-byte header.
	_, err := network.DecodeMessage(bytes.NewReader(make([]byte, 10)), testMagic)
	if err == nil {
		t.Error("expected error for truncated header")
	}
}

// ── VersionMsg ────────────────────────────────────────────────────────────────

func TestVersionMsg_RoundTrip(t *testing.T) {
	original := &network.VersionMsg{
		Version:     70001,
		Services:    1,
		Timestamp:   time.Now().Unix(),
		AddrRecv:    "127.0.0.1:9333",
		AddrFrom:    "192.168.1.1:9333",
		Nonce:       0xDEADBEEF,
		UserAgent:   "/Malairted:0.1.0/",
		StartHeight: 42,
	}

	encoded := original.Encode()
	decoded, err := network.DecodeVersionMsg(encoded)
	if err != nil {
		t.Fatalf("DecodeVersionMsg: %v", err)
	}

	if decoded.Version != original.Version {
		t.Errorf("Version: got %d, want %d", decoded.Version, original.Version)
	}
	if decoded.Services != original.Services {
		t.Errorf("Services: got %d, want %d", decoded.Services, original.Services)
	}
	if decoded.Timestamp != original.Timestamp {
		t.Errorf("Timestamp: got %d, want %d", decoded.Timestamp, original.Timestamp)
	}
	if decoded.UserAgent != original.UserAgent {
		t.Errorf("UserAgent: got %q, want %q", decoded.UserAgent, original.UserAgent)
	}
	if decoded.StartHeight != original.StartHeight {
		t.Errorf("StartHeight: got %d, want %d", decoded.StartHeight, original.StartHeight)
	}
	if decoded.AddrRecv != original.AddrRecv {
		t.Errorf("AddrRecv: got %q, want %q", decoded.AddrRecv, original.AddrRecv)
	}
	if decoded.Nonce != original.Nonce {
		t.Errorf("Nonce: got %x, want %x", decoded.Nonce, original.Nonce)
	}
}

func TestDecodeVersionMsg_TooShort(t *testing.T) {
	_, err := network.DecodeVersionMsg([]byte{0x01, 0x00}) // way too short
	if err == nil {
		t.Error("expected error for truncated version msg")
	}
}

// ── PingMsg / PongMsg ─────────────────────────────────────────────────────────

func TestPingMsg_RoundTrip(t *testing.T) {
	original := &network.PingMsg{Nonce: 0xCAFEBABE_DEADBEEF}
	decoded, err := network.DecodePingMsg(original.Encode())
	if err != nil {
		t.Fatalf("DecodePingMsg: %v", err)
	}
	if decoded.Nonce != original.Nonce {
		t.Errorf("Nonce: got %x, want %x", decoded.Nonce, original.Nonce)
	}
}

func TestPongMsg_RoundTrip(t *testing.T) {
	original := &network.PongMsg{Nonce: 12345678}
	decoded, err := network.DecodePongMsg(original.Encode())
	if err != nil {
		t.Fatalf("DecodePongMsg: %v", err)
	}
	if decoded.Nonce != original.Nonce {
		t.Errorf("Nonce: got %d, want %d", decoded.Nonce, original.Nonce)
	}
}

func TestDecodePingMsg_TooShort(t *testing.T) {
	_, err := network.DecodePingMsg([]byte{0x01, 0x02}) // 2 bytes, need 8
	if err == nil {
		t.Error("expected error for truncated ping msg")
	}
}

// ── InvMsg ────────────────────────────────────────────────────────────────────

func TestInvMsg_RoundTrip_Empty(t *testing.T) {
	original := &network.InvMsg{Items: []network.InvVect{}}
	decoded, err := network.DecodeInvMsg(original.Encode())
	if err != nil {
		t.Fatalf("DecodeInvMsg: %v", err)
	}
	if len(decoded.Items) != 0 {
		t.Errorf("Items count: got %d, want 0", len(decoded.Items))
	}
}

func TestInvMsg_RoundTrip_WithItems(t *testing.T) {
	var hash1, hash2 [32]byte
	hash1[0] = 0xAA
	hash2[31] = 0xBB
	original := &network.InvMsg{
		Items: []network.InvVect{
			{Type: network.InvTypeBlock, Hash: hash1},
			{Type: network.InvTypeTx, Hash: hash2},
		},
	}
	decoded, err := network.DecodeInvMsg(original.Encode())
	if err != nil {
		t.Fatalf("DecodeInvMsg: %v", err)
	}
	if len(decoded.Items) != 2 {
		t.Fatalf("Items count: got %d, want 2", len(decoded.Items))
	}
	if decoded.Items[0].Type != network.InvTypeBlock {
		t.Errorf("Items[0].Type: got %d, want %d (InvTypeBlock)", decoded.Items[0].Type, network.InvTypeBlock)
	}
	if decoded.Items[0].Hash != hash1 {
		t.Errorf("Items[0].Hash mismatch")
	}
	if decoded.Items[1].Type != network.InvTypeTx {
		t.Errorf("Items[1].Type: got %d, want %d (InvTypeTx)", decoded.Items[1].Type, network.InvTypeTx)
	}
	if decoded.Items[1].Hash != hash2 {
		t.Errorf("Items[1].Hash mismatch")
	}
}

func TestDecodeInvMsg_Truncated(t *testing.T) {
	// Encode an InvMsg claiming 3 items but only include 1 item's worth of data.
	original := &network.InvMsg{
		Items: []network.InvVect{
			{Type: network.InvTypeBlock, Hash: [32]byte{0x01}},
		},
	}
	data := original.Encode()
	// Overwrite the count byte to claim 3 items but data only holds 1.
	data[0] = 3
	_, err := network.DecodeInvMsg(data)
	if err == nil {
		t.Error("expected error for truncated inv msg")
	}
}

// ── GetBlocksMsg ──────────────────────────────────────────────────────────────

func TestGetBlocksMsg_RoundTrip(t *testing.T) {
	var h1, h2, stop [32]byte
	h1[0] = 0x01
	h2[0] = 0x02
	stop[0] = 0xFF
	original := &network.GetBlocksMsg{
		BlockLocator: [][32]byte{h1, h2},
		StopHash:     stop,
	}
	decoded, err := network.DecodeGetBlocksMsg(original.Encode())
	if err != nil {
		t.Fatalf("DecodeGetBlocksMsg: %v", err)
	}
	if len(decoded.BlockLocator) != 2 {
		t.Fatalf("BlockLocator count: got %d, want 2", len(decoded.BlockLocator))
	}
	if decoded.BlockLocator[0] != h1 {
		t.Errorf("BlockLocator[0] mismatch")
	}
	if decoded.BlockLocator[1] != h2 {
		t.Errorf("BlockLocator[1] mismatch")
	}
	if decoded.StopHash != stop {
		t.Errorf("StopHash mismatch: got %x, want %x", decoded.StopHash, stop)
	}
}

func TestGetBlocksMsg_EmptyLocator(t *testing.T) {
	original := &network.GetBlocksMsg{
		BlockLocator: [][32]byte{},
		StopHash:     [32]byte{},
	}
	decoded, err := network.DecodeGetBlocksMsg(original.Encode())
	if err != nil {
		t.Fatalf("DecodeGetBlocksMsg: %v", err)
	}
	if len(decoded.BlockLocator) != 0 {
		t.Errorf("BlockLocator count: got %d, want 0", len(decoded.BlockLocator))
	}
}

// ── HeadersMsg ────────────────────────────────────────────────────────────────

func TestHeadersMsg_RoundTrip(t *testing.T) {
	hdr1 := primitives.BlockHeader{
		Version:  1,
		Height:   1,
		Bits:     0x207fffff,
		Nonce:    42,
		Timestamp: 1_704_067_200,
	}
	hdr1.PreviousHash[0] = 0xAA
	hdr1.MerkleRoot[0] = 0xBB

	hdr2 := primitives.BlockHeader{
		Version:  1,
		Height:   2,
		Bits:     0x207fffff,
		Nonce:    99,
		Timestamp: 1_704_067_320,
	}

	original := &network.HeadersMsg{Headers: []primitives.BlockHeader{hdr1, hdr2}}
	decoded, err := network.DecodeHeadersMsg(original.Encode())
	if err != nil {
		t.Fatalf("DecodeHeadersMsg: %v", err)
	}
	if len(decoded.Headers) != 2 {
		t.Fatalf("Headers count: got %d, want 2", len(decoded.Headers))
	}
	if decoded.Headers[0].Height != hdr1.Height {
		t.Errorf("Headers[0].Height: got %d, want %d", decoded.Headers[0].Height, hdr1.Height)
	}
	if decoded.Headers[0].Nonce != hdr1.Nonce {
		t.Errorf("Headers[0].Nonce: got %d, want %d", decoded.Headers[0].Nonce, hdr1.Nonce)
	}
	if decoded.Headers[0].PreviousHash != hdr1.PreviousHash {
		t.Errorf("Headers[0].PreviousHash mismatch")
	}
	if decoded.Headers[1].Height != hdr2.Height {
		t.Errorf("Headers[1].Height: got %d, want %d", decoded.Headers[1].Height, hdr2.Height)
	}
}

func TestHeadersMsg_Empty(t *testing.T) {
	original := &network.HeadersMsg{Headers: []primitives.BlockHeader{}}
	decoded, err := network.DecodeHeadersMsg(original.Encode())
	if err != nil {
		t.Fatalf("DecodeHeadersMsg: %v", err)
	}
	if len(decoded.Headers) != 0 {
		t.Errorf("Headers count: got %d, want 0", len(decoded.Headers))
	}
}

// ── VerAckMsg ─────────────────────────────────────────────────────────────────

func TestVerAckMsg_EmptyPayload(t *testing.T) {
	msg := &network.VerAckMsg{}
	if len(msg.Encode()) != 0 {
		t.Errorf("VerAck payload should be 0 bytes, got %d", len(msg.Encode()))
	}
}
