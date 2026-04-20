package network

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/computervirtualservices/malairte/internal/chain"
)

// newV2TestParams returns a minimal ChainParams sufficient for Peer-level
// tests: the Peer only reads MagicBytes() which comes from params.Net.
func newV2TestParams() *chain.ChainParams {
	return &chain.ChainParams{
		Name: "v2test",
		Net:  0x4d4c5254, // "MLRT"
	}
}

// handshakePair runs InitiateV2 and AcceptV2 on both ends of a net.Pipe in
// parallel and returns the two sessions. Fatals the test if either side
// fails. The pipe itself is returned so the caller can exchange packets.
func handshakePair(t *testing.T) (*Session, *Session, net.Conn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()

	var (
		sessA, sessB *Session
		errA, errB   error
		wg           sync.WaitGroup
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		sessA, errA = InitiateV2(a)
	}()
	go func() {
		defer wg.Done()
		sessB, errB = AcceptV2(b)
	}()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		a.Close()
		b.Close()
		t.Fatal("v2 handshake timed out")
	}
	if errA != nil {
		t.Fatalf("InitiateV2: %v", errA)
	}
	if errB != nil {
		t.Fatalf("AcceptV2: %v", errB)
	}
	return sessA, sessB, a, b
}

func TestV2Transport_RoundTrip(t *testing.T) {
	sessA, sessB, a, b := handshakePair(t)
	defer a.Close()
	defer b.Close()

	// Initiator → responder
	msg1 := []byte("hello from initiator")
	go func() {
		if err := sessA.WritePacket(a, msg1); err != nil {
			t.Errorf("A write: %v", err)
		}
	}()
	got1, err := sessB.ReadPacket(b)
	if err != nil {
		t.Fatalf("B read: %v", err)
	}
	if !bytes.Equal(got1, msg1) {
		t.Errorf("msg1 round-trip: got %q, want %q", got1, msg1)
	}

	// Responder → initiator
	msg2 := []byte("hello from responder")
	go func() {
		if err := sessB.WritePacket(b, msg2); err != nil {
			t.Errorf("B write: %v", err)
		}
	}()
	got2, err := sessA.ReadPacket(a)
	if err != nil {
		t.Fatalf("A read: %v", err)
	}
	if !bytes.Equal(got2, msg2) {
		t.Errorf("msg2 round-trip: got %q, want %q", got2, msg2)
	}
}

func TestV2Transport_MultiplePackets(t *testing.T) {
	// Proves the nonce counters stay in lock-step across many packets.
	sessA, sessB, a, b := handshakePair(t)
	defer a.Close()
	defer b.Close()

	const N = 50
	go func() {
		for i := 0; i < N; i++ {
			payload := bytes.Repeat([]byte{byte(i)}, (i%13)+1)
			if err := sessA.WritePacket(a, payload); err != nil {
				t.Errorf("A write %d: %v", i, err)
				return
			}
		}
	}()
	for i := 0; i < N; i++ {
		expected := bytes.Repeat([]byte{byte(i)}, (i%13)+1)
		got, err := sessB.ReadPacket(b)
		if err != nil {
			t.Fatalf("B read %d: %v", i, err)
		}
		if !bytes.Equal(got, expected) {
			t.Errorf("packet %d: got %x, want %x", i, got, expected)
		}
	}
}

// buffered provides a Read/Write buffer pair that captures writes so tests
// can tamper with on-wire bytes before the peer reads them.
type buffered struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *buffered) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *buffered) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.buf.Len() == 0 {
		return 0, io.EOF
	}
	return b.buf.Read(p)
}

func (b *buffered) bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buf.Bytes()...)
}

func (b *buffered) reset(contents []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.Reset()
	b.buf.Write(contents)
}

func TestV2Transport_TamperedPayloadFailsAuth(t *testing.T) {
	sessA, sessB, a, b := handshakePair(t)
	defer a.Close()
	defer b.Close()

	// Have A write to a buffer instead of the network.
	var captured buffered
	if err := sessA.WritePacket(&captured, []byte("sensitive payload")); err != nil {
		t.Fatal(err)
	}
	onWire := captured.bytes()
	if len(onWire) < 3+16+1 {
		t.Fatalf("captured packet too short: %d", len(onWire))
	}
	// Flip a bit in the ciphertext (skip the 3-byte length prefix).
	onWire[3+2] ^= 0x01

	// Feed the tampered bytes into B's side of the pipe.
	go func() {
		a.Write(onWire)
		a.Close()
	}()
	if _, err := sessB.ReadPacket(b); err == nil {
		t.Error("tampered payload must fail authentication")
	} else if !errors.Is(err, err) { // always true, but documents intent
		t.Logf("got expected auth failure: %v", err)
	}
}

func TestV2Transport_TamperedLengthFailsAuth(t *testing.T) {
	sessA, sessB, a, b := handshakePair(t)
	defer a.Close()
	defer b.Close()

	var captured buffered
	if err := sessA.WritePacket(&captured, []byte("payload")); err != nil {
		t.Fatal(err)
	}
	onWire := captured.bytes()
	if len(onWire) < 3 {
		t.Fatalf("captured too short: %d", len(onWire))
	}
	// Flip a bit in the encrypted length prefix. After XORing with the
	// keystream, this yields a different plaintext length, which will
	// mis-frame the rest of the stream and fail either read or auth.
	onWire[0] ^= 0x01

	go func() {
		a.Write(onWire)
		a.Close()
	}()
	if _, err := sessB.ReadPacket(b); err == nil {
		t.Error("tampered length prefix must fail the read")
	} else {
		t.Logf("got expected framing/auth failure: %v", err)
	}
}

// TestPeer_V2Encrypted_Integration stands up two Peers connected via
// net.Pipe, runs the v2 handshake on both ends, exchanges a single
// NetMessage through the Peer.Send queue, and verifies the decoded message
// arrives intact. This exercises the full path: EnableV2 → Start → Send →
// WritePacket → ReadPacket → DecodeMessage → msgCh.
func TestPeer_V2Encrypted_Integration(t *testing.T) {
	a, b := net.Pipe()

	// Use the package's test ChainParams stub — minimal fields the peer layer
	// reads: Net (for magic bytes).
	params := newV2TestParams()

	peerA := NewPeer(a, params, false) // outbound
	peerB := NewPeer(b, params, true)  // inbound

	// Handshake on both ends concurrently.
	var wg sync.WaitGroup
	wg.Add(2)
	var errA, errB error
	go func() { defer wg.Done(); errA = peerA.EnableV2(true) }()
	go func() { defer wg.Done(); errB = peerB.EnableV2(false) }()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		peerA.Disconnect()
		peerB.Disconnect()
		t.Fatal("handshake timed out")
	}
	if errA != nil {
		t.Fatalf("peerA EnableV2: %v", errA)
	}
	if errB != nil {
		t.Fatalf("peerB EnableV2: %v", errB)
	}

	// Start both peers. Each delivers received messages on msgCh.
	msgChA := make(chan PeerMessage, 4)
	msgChB := make(chan PeerMessage, 4)
	peerA.Start(msgChA)
	peerB.Start(msgChB)
	defer peerA.Disconnect()
	defer peerB.Disconnect()

	// peerA sends a ping; peerB should receive it, decrypted.
	const nonce uint64 = 0xDEADBEEF_CAFEBABE
	peerA.SendPing(nonce)

	select {
	case pm := <-msgChB:
		if pm.Message.Command != CmdPing {
			t.Errorf("expected ping, got %q", pm.Message.Command)
		}
		ping, err := DecodePingMsg(pm.Message.Payload)
		if err != nil {
			t.Fatalf("DecodePingMsg: %v", err)
		}
		if ping.Nonce != nonce {
			t.Errorf("nonce: got %x, want %x", ping.Nonce, nonce)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ping not delivered within 3s")
	}
}

func TestGetHeadersMsg_RoundTrip(t *testing.T) {
	// The on-wire format must match GetBlocksMsg (we intentionally
	// reuse it). Encode a GetHeaders, decode as both types, assert
	// field equality.
	orig := &GetHeadersMsg{
		BlockLocator: [][32]byte{{0x01}, {0x02}, {0x03}},
		StopHash:     [32]byte{0xAA, 0xBB},
	}
	raw := orig.Encode()
	// Decode back via the dedicated decoder.
	got, err := DecodeGetHeadersMsg(raw)
	if err != nil {
		t.Fatalf("DecodeGetHeadersMsg: %v", err)
	}
	if len(got.BlockLocator) != len(orig.BlockLocator) {
		t.Fatalf("locator len: got %d, want %d", len(got.BlockLocator), len(orig.BlockLocator))
	}
	for i, h := range orig.BlockLocator {
		if got.BlockLocator[i] != h {
			t.Errorf("locator[%d]: got %x, want %x", i, got.BlockLocator[i], h)
		}
	}
	if got.StopHash != orig.StopHash {
		t.Errorf("stopHash: got %x, want %x", got.StopHash, orig.StopHash)
	}
	// Wire-format compatible with GetBlocksMsg.
	if _, err := DecodeGetBlocksMsg(raw); err != nil {
		t.Errorf("GetHeaders wire form must also decode as GetBlocks: %v", err)
	}
}

func TestV2Transport_IndependentSessionsHaveDifferentKeys(t *testing.T) {
	// Two independent handshakes between different ephemeral keys must
	// produce different session keys — i.e. a ciphertext from session #1
	// must not decrypt under session #2.
	sessA1, sessB1, a1, b1 := handshakePair(t)
	defer a1.Close()
	defer b1.Close()
	_, sessB2, _, _ := handshakePair(t)

	var captured buffered
	if err := sessA1.WritePacket(&captured, []byte("session 1 secret")); err != nil {
		t.Fatal(err)
	}

	// Feed session 1's packet to session 2 — auth must fail.
	go func() {
		a1.Write(captured.bytes())
		a1.Close()
	}()
	if _, err := sessB2.ReadPacket(b1); err == nil {
		t.Error("cross-session decryption must fail")
	}
	_ = sessB1 // keep variable referenced; not needed for the assertion
}
