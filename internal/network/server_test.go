package network

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/computervirtualservices/malairte/internal/chain"
	"github.com/computervirtualservices/malairte/internal/mempool"
	"github.com/computervirtualservices/malairte/internal/storage"
)

// newTestPeer builds a Peer backed by a net.Pipe connection so we get a real
// net.Conn without opening OS sockets. The pipe addr ("pipe") is overwritten
// with the caller-supplied value so multiple peers don't collide in the
// peer map keyed by address.
func newTestPeer(t *testing.T, addr string, startHeight int32) *Peer {
	t.Helper()
	connA, connB := net.Pipe()
	t.Cleanup(func() {
		_ = connA.Close()
		_ = connB.Close()
	})
	params := chain.MainNetParams
	p := NewPeer(connA, &params, true)
	p.addr = addr
	p.SetVersion(protocolVersion, 0, "/test/", startHeight)
	return p
}

func TestBestPeerHeight_NoPeers(t *testing.T) {
	s := &PeerServer{peers: make(map[string]*Peer)}
	h, n := s.BestPeerHeight()
	if h != 0 || n != 0 {
		t.Fatalf("expected (0, 0), got (%d, %d)", h, n)
	}
}

func TestBestPeerHeight_TakesMaximum(t *testing.T) {
	s := &PeerServer{peers: make(map[string]*Peer)}
	s.peers["a"] = newTestPeer(t, "a", 10)
	s.peers["b"] = newTestPeer(t, "b", 619)
	s.peers["c"] = newTestPeer(t, "c", 42)

	h, n := s.BestPeerHeight()
	if h != 619 {
		t.Fatalf("best height = %d, want 619", h)
	}
	if n != 3 {
		t.Fatalf("peer count = %d, want 3", n)
	}
}

// newTestServer stands up a PeerServer backed by a real in-memory chain so
// WaitForInitialSync can observe BestHeight() advancing against peer
// StartHeight. Uses t.TempDir() so Badger files are cleaned up automatically.
func newTestServer(t *testing.T) *PeerServer {
	t.Helper()
	db, err := storage.OpenBadger(t.TempDir())
	if err != nil {
		t.Fatalf("open badger: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	params := chain.MainNetParams
	bc, err := chain.NewBlockchain(&params, db)
	if err != nil {
		t.Fatalf("new blockchain: %v", err)
	}
	return &PeerServer{
		bc:    bc,
		pool:  mempool.NewTxPool(),
		peers: make(map[string]*Peer),
		quit:  make(chan struct{}),
	}
}

func TestWaitForInitialSync_AlreadySyncedReturnsImmediately(t *testing.T) {
	s := newTestServer(t)
	// Peer claims height 0; fresh bc is at height 0 too, so we are synced.
	s.peers["a"] = newTestPeer(t, "a", 0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	if err := s.WaitForInitialSync(ctx); err != nil {
		t.Fatalf("WaitForInitialSync: %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("expected fast return, took %v", d)
	}
}

func TestWaitForInitialSync_ContextCancelUnblocks(t *testing.T) {
	s := newTestServer(t)
	// Peer is 1000 blocks ahead and we have no way to catch up in a unit test,
	// so the wait should block until the context expires.
	s.peers["a"] = newTestPeer(t, "a", 1000)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := s.WaitForInitialSync(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected non-nil error when context is cancelled")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("WaitForInitialSync took too long to honor cancel: %v", elapsed)
	}
}

func TestWaitForInitialSync_QuitUnblocks(t *testing.T) {
	s := newTestServer(t)
	s.peers["a"] = newTestPeer(t, "a", 1000)

	// Close quit after a short delay; WaitForInitialSync must return.
	go func() {
		time.Sleep(50 * time.Millisecond)
		close(s.quit)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.WaitForInitialSync(ctx); err == nil {
		t.Fatal("expected error when peer server is stopped")
	}
}
