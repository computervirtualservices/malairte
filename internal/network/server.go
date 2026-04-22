package network

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/computervirtualservices/malairte/internal/chain"
	"github.com/computervirtualservices/malairte/internal/consensus"
	"github.com/computervirtualservices/malairte/internal/mempool"
	"github.com/computervirtualservices/malairte/internal/primitives"
)

// protocolVersion is the current P2P protocol version.
const protocolVersion uint32 = 70001

// userAgent is the software version string sent in version messages.
const userAgent = "/Malairted:0.1.0/"

// defaultMaxPeers is the fallback cap on simultaneous P2P connections when
// the caller does not set a value via SetMaxPeers.
const defaultMaxPeers = 125

// PeerServer manages all inbound and outbound peer connections.
// It processes incoming messages and coordinates chain sync.
type PeerServer struct {
	bc           *chain.Blockchain
	pool         *mempool.TxPool
	orphans      *mempool.OrphanPool
	params       *chain.ChainParams
	peers        map[string]*Peer
	mu           sync.RWMutex
	listen       net.Listener
	msgCh        chan PeerMessage
	quit         chan struct{}
	stopOnce     sync.Once
	maxPeers     int
	lastSyncReq  time.Time // last time any getblocks was sent for sync
	syncReqMu    sync.Mutex
}

// NewPeerServer creates a new P2P server.
func NewPeerServer(bc *chain.Blockchain, pool *mempool.TxPool, params *chain.ChainParams) *PeerServer {
	return &PeerServer{
		bc:       bc,
		pool:     pool,
		orphans:  mempool.NewOrphanPool(defaultOrphanCapacity),
		params:   params,
		peers:    make(map[string]*Peer),
		msgCh:    make(chan PeerMessage, 256),
		quit:     make(chan struct{}),
		maxPeers: defaultMaxPeers,
	}
}

// defaultOrphanCapacity caps how many parent-less transactions we hold at
// once — a peer flooding us with fake orphans can't grow the pool beyond this.
const defaultOrphanCapacity = 100

// SetMaxPeers overrides the default inbound-peer cap. Values < 1 are ignored.
// Must be called before Start().
func (s *PeerServer) SetMaxPeers(n int) {
	if n < 1 {
		return
	}
	s.maxPeers = n
}

// Start begins listening for inbound connections and processing messages.
// addr should be "host:port" (e.g. "0.0.0.0:9333").
func (s *PeerServer) Start(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	s.listen = ln
	log.Printf("[p2p] listening on %s", addr)

	// Start message processing goroutine
	go s.messageLoop()

	// Start accept loop
	go s.acceptLoop()

	// Start keepalive/ping loop
	go s.pingLoop()

	// Periodically check if any peer is ahead of us and pull their chain.
	go s.syncLoop()

	return nil
}

// Stop shuts down the P2P server and disconnects all peers. Safe to call multiple times.
func (s *PeerServer) Stop() {
	s.stopOnce.Do(func() {
		close(s.quit)
	})
	if s.listen != nil {
		s.listen.Close()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, peer := range s.peers {
		peer.Disconnect()
	}
}

// ConnectPeer dials an outbound connection to the given address.
func (s *PeerServer) ConnectPeer(addr string) error {
	if s.isSelfAddr(addr) {
		return fmt.Errorf("refusing self-dial to %s", addr)
	}
	if s.hasPeer(addr) {
		return fmt.Errorf("already connected to %s", addr)
	}
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	peer := NewPeer(conn, s.params, false)

	// Negotiate the encrypted transport BEFORE any goroutines touch the
	// conn. Outbound side plays the initiator role.
	if err := peer.EnableV2(true); err != nil {
		conn.Close()
		return fmt.Errorf("v2 handshake with %s: %w", addr, err)
	}

	s.addPeer(peer)
	done := peer.Start(s.msgCh)
	go func() {
		<-done
		s.removePeer(peer.Addr())
		log.Printf("[p2p] peer %s disconnected", peer.Addr())
	}()

	// Initiate version handshake (inside the encrypted tunnel).
	peer.SendVersion(protocolVersion, 0, userAgent, int32(s.bc.BestHeight()))
	log.Printf("[p2p] connected to outbound peer %s (v2 encrypted)", addr)
	return nil
}

// BroadcastBlock announces a new block to all connected peers via an InvMsg.
func (s *PeerServer) BroadcastBlock(block *primitives.Block) {
	hash := block.Header.Hash()
	inv := []InvVect{{Type: InvTypeBlock, Hash: hash}}
	s.broadcast(CmdInv, (&InvMsg{Items: inv}).Encode())
	log.Printf("[p2p] broadcast block %x to %d peers", hash, s.PeerCount())
}

// BroadcastTx announces a new transaction to all connected peers via an InvMsg.
func (s *PeerServer) BroadcastTx(tx *primitives.Transaction) {
	txid := tx.TxID()
	inv := []InvVect{{Type: InvTypeTx, Hash: txid}}
	s.broadcast(CmdInv, (&InvMsg{Items: inv}).Encode())
}

// PeerCount returns the number of currently connected peers.
func (s *PeerServer) PeerCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.peers)
}

// BestPeerHeight returns the highest startheight advertised by any connected
// peer together with the number of peers currently connected. When no peers
// are connected it returns (0, 0).
func (s *PeerServer) BestPeerHeight() (int32, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var best int32
	for _, p := range s.peers {
		if h := p.StartHeight(); h > best {
			best = h
		}
	}
	return best, len(s.peers)
}

// WaitForInitialSync blocks until the local chain has caught up to the best
// height advertised by connected peers, or until ctx is done.
//
// The caller is responsible for setting a deadline on ctx; this function will
// otherwise wait indefinitely for a peer to appear. On ctx expiry the
// function returns ctx.Err() — callers that still want to proceed (e.g. to
// mine locally while offline) should treat context.DeadlineExceeded as a
// warning rather than a fatal error.
//
// The function treats "no peers connected" as "not yet synced" so that a
// fresh install with seeds configured cannot race past the wait before the
// first handshake completes. Once at least one peer has reported its
// startheight, sync is considered complete when our tip reaches that height.
func (s *PeerServer) WaitForInitialSync(ctx context.Context) error {
	const (
		pollInterval  = 1 * time.Second
		logInterval   = 10 * time.Second
		peerGraceTime = 15 * time.Second
	)

	start := time.Now()
	lastLog := time.Now().Add(-logInterval)

	for {
		ours := s.bc.BestHeight()
		best, peers := s.BestPeerHeight()

		switch {
		case peers == 0:
			if time.Since(start) >= peerGraceTime && time.Since(lastLog) >= logInterval {
				log.Printf("[sync] waiting for peers before mining (our height=%d)", ours)
				lastLog = time.Now()
			}
		case uint64(best) <= ours:
			log.Printf("[sync] initial sync complete: height=%d peers=%d", ours, peers)
			return nil
		default:
			if time.Since(lastLog) >= logInterval {
				log.Printf("[sync] catching up: our=%d best-peer=%d peers=%d", ours, best, peers)
				lastLog = time.Now()
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.quit:
			return fmt.Errorf("peer server stopped")
		case <-time.After(pollInterval):
		}
	}
}

// GetPeers returns a snapshot of currently connected peer addresses.
func (s *PeerServer) GetPeers() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	addrs := make([]string, 0, len(s.peers))
	for addr := range s.peers {
		addrs = append(addrs, addr)
	}
	return addrs
}

// GetPeerInfo returns a slice of peer info maps for the RPC getpeerinfo call.
func (s *PeerServer) GetPeerInfo() []map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]map[string]interface{}, 0, len(s.peers))
	for _, p := range s.peers {
		result = append(result, map[string]interface{}{
			"addr":        p.Addr(),
			"inbound":     p.IsInbound(),
			"useragent":   p.UserAgent(),
			"startheight": p.StartHeight(),
			"version":     protocolVersion,
		})
	}
	return result
}

// acceptLoop accepts inbound connections from the listener.
func (s *PeerServer) acceptLoop() {
	for {
		conn, err := s.listen.Accept()
		if err != nil {
			select {
			case <-s.quit:
				return
			default:
				log.Printf("[p2p] accept error: %v", err)
				continue
			}
		}

		if s.PeerCount() >= s.maxPeers {
			log.Printf("[p2p] max peers reached (%d), rejecting %s", s.maxPeers, conn.RemoteAddr())
			conn.Close()
			continue
		}

		peer := NewPeer(conn, s.params, true)

		// Run the encrypted-transport handshake on a background goroutine so
		// a slow or misbehaving peer can't stall the accept loop. On failure
		// we drop the connection without adding it to the peer set.
		go func(p *Peer, c net.Conn) {
			if err := p.EnableV2(false); err != nil {
				log.Printf("[p2p] v2 handshake with inbound %s failed: %v", c.RemoteAddr(), err)
				c.Close()
				return
			}
			s.addPeer(p)
			done := p.Start(s.msgCh)
			log.Printf("[p2p] accepted inbound peer %s (v2 encrypted)", c.RemoteAddr())
			<-done
			s.removePeer(p.Addr())
			log.Printf("[p2p] inbound peer %s disconnected", p.Addr())
		}(peer, conn)
	}
}

// messageLoop processes messages from all peers sequentially.
func (s *PeerServer) messageLoop() {
	for {
		select {
		case pm := <-s.msgCh:
			s.handleMessage(pm)
		case <-s.quit:
			return
		}
	}
}

// pingLoop periodically pings all connected peers to detect dead connections.
func (s *PeerServer) pingLoop() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			nonce := uint64(rand.Int63())
			s.mu.RLock()
			for _, p := range s.peers {
				p.SendPing(nonce)
			}
			s.mu.RUnlock()
		case <-s.quit:
			return
		}
	}
}

// handleMessage dispatches a received message to the appropriate handler.
func (s *PeerServer) handleMessage(pm PeerMessage) {
	peer := pm.Peer
	msg := pm.Message

	switch msg.Command {
	case CmdVersion:
		s.handleVersion(peer, msg.Payload)
	case CmdVerAck:
		// Handshake complete; nothing to do here
		log.Printf("[p2p] verack from %s", peer.Addr())
	case CmdPing:
		s.handlePing(peer, msg.Payload)
	case CmdPong:
		// Pong received; connection is alive
	case CmdInv:
		s.handleInv(peer, msg.Payload)
	case CmdGetData:
		s.handleGetData(peer, msg.Payload)
	case CmdBlock:
		s.handleBlock(peer, msg.Payload)
	case CmdTx:
		s.handleTx(peer, msg.Payload)
	case CmdGetBlocks:
		s.handleGetBlocks(peer, msg.Payload)
	case CmdGetHeaders:
		s.handleGetHeaders(peer, msg.Payload)
	case CmdHeaders:
		s.handleHeaders(peer, msg.Payload)
	default:
		log.Printf("[p2p] unknown message command %q from %s", msg.Command, peer.Addr())
	}
}

func (s *PeerServer) handleVersion(peer *Peer, payload []byte) {
	ver, err := DecodeVersionMsg(payload)
	if err != nil {
		log.Printf("[p2p] invalid version msg from %s: %v", peer.Addr(), err)
		peer.Disconnect()
		return
	}
	peer.SetVersion(ver.Version, ver.Services, ver.UserAgent, ver.StartHeight)
	log.Printf("[p2p] version from %s: agent=%s height=%d", peer.Addr(), ver.UserAgent, ver.StartHeight)
	peer.SendVerAck()
	// If outbound, we already sent version; if inbound, respond with our version
	if peer.IsInbound() {
		peer.SendVersion(protocolVersion, 0, userAgent, int32(s.bc.BestHeight()))
	}
	// If the peer is ahead of us, request their blocks immediately
	if uint64(ver.StartHeight) > s.bc.BestHeight() {
		locator := s.BlockLocator()
		getBlocks := &GetBlocksMsg{BlockLocator: locator}
		peer.Send(&NetMessage{Command: CmdGetBlocks, Payload: getBlocks.Encode()})
		log.Printf("[p2p] requesting sync from %s (peer height=%d, ours=%d)",
			peer.Addr(), ver.StartHeight, s.bc.BestHeight())
	}
}

func (s *PeerServer) handlePing(peer *Peer, payload []byte) {
	ping, err := DecodePingMsg(payload)
	if err != nil {
		return
	}
	pong := &PongMsg{Nonce: ping.Nonce}
	peer.Send(&NetMessage{Command: CmdPong, Payload: pong.Encode()})
}

func (s *PeerServer) handleInv(peer *Peer, payload []byte) {
	inv, err := DecodeInvMsg(payload)
	if err != nil {
		log.Printf("[p2p] invalid inv from %s: %v", peer.Addr(), err)
		return
	}
	// Request items we don't have
	var wanted []InvVect
	for _, item := range inv.Items {
		switch item.Type {
		case InvTypeBlock:
			if _, err := s.bc.GetBlock(item.Hash); err != nil {
				wanted = append(wanted, item)
			}
		case InvTypeTx:
			if !s.pool.Has(item.Hash) {
				wanted = append(wanted, item)
			}
		}
	}
	if len(wanted) > 0 {
		getData := &InvMsg{Items: wanted}
		peer.Send(&NetMessage{Command: CmdGetData, Payload: getData.Encode()})
	}
}

func (s *PeerServer) handleGetData(peer *Peer, payload []byte) {
	req, err := DecodeInvMsg(payload)
	if err != nil {
		return
	}
	for _, item := range req.Items {
		switch item.Type {
		case InvTypeBlock:
			block, err := s.bc.GetBlock(item.Hash)
			if err != nil {
				continue
			}
			peer.Send(&NetMessage{Command: CmdBlock, Payload: block.Serialize()})
		case InvTypeTx:
			tx, ok := s.pool.Get(item.Hash)
			if !ok {
				continue
			}
			peer.Send(&NetMessage{Command: CmdTx, Payload: tx.Serialize()})
		}
	}
}

func (s *PeerServer) handleBlock(peer *Peer, payload []byte) {
	blockMsg, err := DecodeBlockMsg(payload)
	if err != nil {
		log.Printf("[p2p] invalid block from %s: %v", peer.Addr(), err)
		return
	}
	hash := blockMsg.Block.Header.Hash()
	if err := s.bc.ProcessBlock(blockMsg.Block); err != nil {
		// Orphan recovery: if the parent is unknown, ask the peer for the
		// missing chain. Throttled so a fast-mining peer can't saturate our
		// send queue with redundant getblocks requests.
		if isMissingParentErr(err) {
			s.maybeRequestSync(peer)
		} else {
			log.Printf("[p2p] rejected block %x from %s: %v", hash, peer.Addr(), err)
		}
		return
	}
	s.pool.RemoveBlock(blockMsg.Block)
	log.Printf("[p2p] accepted block %x height=%d from %s",
		hash, blockMsg.Block.Header.Height, peer.Addr())
	// Relay the block to other peers
	inv := []InvVect{{Type: InvTypeBlock, Hash: hash}}
	s.broadcastExcept(CmdInv, (&InvMsg{Items: inv}).Encode(), peer.Addr())
}

// isMissingParentErr returns true when ProcessBlock rejected the block because
// either the parent header is not in storage OR the block does not extend our
// current tip (meaning we're behind on the chain). Both cases should trigger
// a sync request.
func isMissingParentErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "get previous header") ||
		strings.Contains(msg, "does not extend current tip") ||
		strings.Contains(msg, "is not tip+1")
}

// maybeRequestSync sends a getblocks to the given peer at most once per
// syncThrottle interval. This is the hot path when a fast miner broadcasts
// blocks we can't yet chain; without throttling, every rejected block would
// enqueue another getblocks and saturate the peer's send buffer.
const syncThrottle = 10 * time.Second

func (s *PeerServer) maybeRequestSync(peer *Peer) {
	s.syncReqMu.Lock()
	if time.Since(s.lastSyncReq) < syncThrottle {
		s.syncReqMu.Unlock()
		return
	}
	s.lastSyncReq = time.Now()
	s.syncReqMu.Unlock()

	locator := s.BlockLocator()
	peer.Send(&NetMessage{Command: CmdGetBlocks, Payload: (&GetBlocksMsg{BlockLocator: locator}).Encode()})
	log.Printf("[p2p] sync: requesting blocks from %s (our height=%d)", peer.Addr(), s.bc.BestHeight())
}

// syncLoop periodically checks connected peers; if any advertises a higher
// startheight than our tip and we haven't recently requested sync, send a
// getblocks to pull their chain. Covers the case where a peer's new-block
// broadcast never reaches us (dropped due to saturation, etc.).
func (s *PeerServer) syncLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.quit:
			return
		case <-ticker.C:
			ourHeight := s.bc.BestHeight()
			var bestPeer *Peer
			var bestHeight int32
			s.mu.RLock()
			for _, p := range s.peers {
				if p.StartHeight() > bestHeight {
					bestHeight = p.StartHeight()
					bestPeer = p
				}
			}
			s.mu.RUnlock()
			if bestPeer != nil && uint64(bestHeight) > ourHeight {
				s.maybeRequestSync(bestPeer)
			}
		}
	}
}

func (s *PeerServer) handleTx(peer *Peer, payload []byte) {
	txMsg, err := DecodeTxMsg(payload)
	if err != nil {
		return
	}
	s.acceptOrOrphan(txMsg.Tx, peer.Addr())
}

// acceptOrOrphan feeds a tx through the full admission path:
//  1. Try to resolve fees via UTXO + mempool. If all inputs resolve, run
//     full script validation, Add to the mempool, broadcast INV, and
//     release any orphans waiting for this txid as their parent.
//  2. If some input can't resolve, stash the tx in the orphan pool keyed
//     by the missing parent txid. It will be re-attempted when that parent
//     shows up.
func (s *PeerServer) acceptOrOrphan(tx *primitives.Transaction, sourceAddr string) {
	fee, ok := s.computeFeeFromUTXO(tx)
	if !ok {
		// Can't compute fee → missing parent. Stash as an orphan.
		s.orphans.Add(tx)
		return
	}
	// Script validation — same interpreter pass block validation uses.
	// A tx with bogus signatures is dropped here so we don't waste
	// bandwidth relaying it to other peers or miner effort on blocks
	// that would fail to validate.
	nextHeight := s.bc.BestHeight() + 1
	if err := chain.ValidateTx(tx, s.bc.UTXOSet(), nextHeight, s.params); err != nil {
		log.Printf("[p2p] tx %x rejected at admission: %v", tx.TxID(), err)
		return
	}
	if err := s.pool.Add(tx, fee); err != nil {
		return // duplicate, RBF rejection, or policy-invalid
	}
	txid := tx.TxID()
	log.Printf("[p2p] accepted tx %x from %s (fee=%d atoms)", txid, sourceAddr, fee)
	inv := []InvVect{{Type: InvTypeTx, Hash: txid}}
	s.broadcastExcept(CmdInv, (&InvMsg{Items: inv}).Encode(), sourceAddr)

	// Any orphans that were waiting for THIS tx as their parent can now
	// be re-attempted. Recurse — a newly-admitted orphan may itself
	// unblock further descendants.
	for _, orphan := range s.orphans.Release(txid) {
		s.acceptOrOrphan(orphan, sourceAddr)
	}
}

// computeFeeFromUTXO resolves every input's prevout and returns
// totalIn − totalOut. Inputs are looked up first in the confirmed UTXO set
// and, on miss, in the mempool — this fallback enables CPFP: a child
// transaction whose parent is still unconfirmed can have its fee computed
// and be accepted, so the pair (parent + child) propagates together at
// whatever feerate the child pays on behalf of both.
//
// Returns ok=false only if an input is truly unresolvable (fabricated prevout,
// or output spent elsewhere) or if the result would be negative.
func (s *PeerServer) computeFeeFromUTXO(tx *primitives.Transaction) (int64, bool) {
	utxo := s.bc.UTXOSet()
	var totalIn int64
	for _, in := range tx.Inputs {
		if entry, found := utxo.Get(in.PreviousOutput); found {
			totalIn += entry.Value
			continue
		}
		if out, found := s.pool.GetOutput(in.PreviousOutput); found {
			totalIn += out.Value
			continue
		}
		return 0, false
	}
	var totalOut int64
	for _, out := range tx.Outputs {
		totalOut += out.Value
	}
	if totalIn < totalOut {
		return 0, false
	}
	return totalIn - totalOut, true
}

func (s *PeerServer) handleGetBlocks(peer *Peer, payload []byte) {
	req, err := DecodeGetBlocksMsg(payload)
	if err != nil {
		return
	}

	// Find the highest known block from the locator
	startHeight := uint64(0)
	for _, locHash := range req.BlockLocator {
		if hdr, err := s.bc.GetBlockHeader(locHash); err == nil {
			if hdr.Height > startHeight {
				startHeight = hdr.Height
			}
			break
		}
	}

	// Send up to 500 block hashes starting from startHeight+1
	tipHeight := s.bc.BestHeight()
	inv := make([]InvVect, 0, 500)
	stopHash := req.StopHash

	for h := startHeight + 1; h <= tipHeight && len(inv) < 500; h++ {
		hash, err := s.bc.GetBlockHashAtHeight(h)
		if err != nil {
			break
		}
		inv = append(inv, InvVect{Type: InvTypeBlock, Hash: hash})
		if hash == stopHash {
			break
		}
	}

	if len(inv) > 0 {
		peer.Send(&NetMessage{Command: CmdInv, Payload: (&InvMsg{Items: inv}).Encode()})
	}
}

// handleGetHeaders responds to a peer's header-first sync request: find the
// highest known hash from the locator, then stream up to 2000 consecutive
// headers from there forward (capped at the tip or stopHash). 2000 matches
// Bitcoin Core's headers-message limit — clients that process our reply
// iteratively will walk 2000-at-a-time to catch up.
func (s *PeerServer) handleGetHeaders(peer *Peer, payload []byte) {
	req, err := DecodeGetHeadersMsg(payload)
	if err != nil {
		return
	}
	startHeight := uint64(0)
	for _, locHash := range req.BlockLocator {
		if hdr, err := s.bc.GetBlockHeader(locHash); err == nil {
			if hdr.Height > startHeight {
				startHeight = hdr.Height
			}
			break
		}
	}
	tipHeight := s.bc.BestHeight()
	const maxHeaders = 2000
	headers := make([]primitives.BlockHeader, 0, maxHeaders)
	stopHash := req.StopHash
	for h := startHeight + 1; h <= tipHeight && len(headers) < maxHeaders; h++ {
		hash, err := s.bc.GetBlockHashAtHeight(h)
		if err != nil {
			break
		}
		hdr, err := s.bc.GetBlockHeader(hash)
		if err != nil {
			break
		}
		headers = append(headers, *hdr)
		if hash == stopHash {
			break
		}
	}
	if len(headers) > 0 {
		peer.Send(&NetMessage{Command: CmdHeaders, Payload: (&HeadersMsg{Headers: headers}).Encode()})
	}
}

// handleHeaders processes a "headers" message from a peer.
// For each header the node does not yet have, it validates the PoW claim
// (hash meets the header's own Bits target) and requests the full block via
// getdata.  Full contextual validation (height, previous-hash chain linkage,
// timestamp) happens inside ProcessBlock when the block arrives.
func (s *PeerServer) handleHeaders(peer *Peer, payload []byte) {
	msg, err := DecodeHeadersMsg(payload)
	if err != nil {
		log.Printf("[p2p] invalid headers from %s: %v", peer.Addr(), err)
		return
	}
	if len(msg.Headers) == 0 {
		return
	}

	var wanted []InvVect
	for i := range msg.Headers {
		hdr := &msg.Headers[i]
		hash := hdr.Hash()

		// Skip headers we already have on chain.
		if _, err := s.bc.GetBlockHeader(hash); err == nil {
			continue
		}

		// Reject headers whose hash does not satisfy their advertised difficulty.
		// This is the only check we can do without the full preceding chain context.
		// It prevents a peer from flooding us with fake headers at zero cost.
		if !consensus.HashMeetsDifficulty(hash, hdr.Bits) {
			log.Printf("[p2p] headers: invalid PoW in header %x from %s, disconnecting",
				hash, peer.Addr())
			peer.Disconnect()
			return
		}

		wanted = append(wanted, InvVect{Type: InvTypeBlock, Hash: hash})
	}

	if len(wanted) == 0 {
		return
	}

	peer.Send(&NetMessage{
		Command: CmdGetData,
		Payload: (&InvMsg{Items: wanted}).Encode(),
	})
	log.Printf("[p2p] requested %d block(s) after headers from %s", len(wanted), peer.Addr())
}

// broadcast sends a message to all connected peers.
func (s *PeerServer) broadcast(cmd string, payload []byte) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, peer := range s.peers {
		peer.Send(&NetMessage{Command: cmd, Payload: payload})
	}
}

// broadcastExcept sends a message to all peers except the one with the given address.
func (s *PeerServer) broadcastExcept(cmd string, payload []byte, exceptAddr string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for addr, peer := range s.peers {
		if addr != exceptAddr {
			peer.Send(&NetMessage{Command: cmd, Payload: payload})
		}
	}
}

// addPeer registers a new peer.
func (s *PeerServer) addPeer(peer *Peer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peers[peer.Addr()] = peer
}

// removePeer unregisters a peer by address.
func (s *PeerServer) removePeer(addr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.peers, addr)
}

// ConnectSeeds starts a reconnect loop for each seed address. Each loop
// dials on startup and, whenever the connection to that seed is absent,
// retries at an increasing backoff. Runs for the lifetime of the server.
//
// Deduplicates the input so the same seed doesn't get two reconnect
// goroutines (otherwise every connection attempt opens two sockets to the
// same host). Self-dial attempts are filtered inside ConnectPeer via
// isSelfAddr, so a node whose public IP happens to be in the default seed
// list won't keep bouncing a loopback connection off its own P2P listener.
func (s *PeerServer) ConnectSeeds(seeds []string) {
	seen := make(map[string]struct{}, len(seeds))
	for _, seed := range seeds {
		seed = strings.TrimSpace(seed)
		if seed == "" {
			continue
		}
		if _, dup := seen[seed]; dup {
			continue
		}
		seen[seed] = struct{}{}
		if s.isSelfAddr(seed) {
			log.Printf("[p2p] skipping self-seed %s", seed)
			continue
		}
		go s.seedReconnectLoop(seed)
	}
}

// isSelfAddr reports whether addr resolves to one of this node's local
// interface addresses AND matches our own P2P listen port. Used to prevent
// a seed list that contains our own public IP (e.g. on the seed node itself)
// from triggering an outbound dial to ourselves — which wastes CPU on the
// BIP-324 handshake and inflates the getpeerinfo response with phantom
// entries.
func (s *PeerServer) isSelfAddr(addr string) bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if s.listen == nil {
		return false
	}
	_, localPort, err := net.SplitHostPort(s.listen.Addr().String())
	if err != nil {
		return false
	}
	if port != localPort {
		return false
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return false
	}
	local, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, ip := range ips {
		if ip.IsLoopback() {
			return true
		}
		for _, la := range local {
			ipnet, ok := la.(*net.IPNet)
			if !ok {
				continue
			}
			if ipnet.IP.Equal(ip) {
				return true
			}
		}
	}
	return false
}

// seedReconnectLoop dials addr and keeps it connected. If the peer disconnects,
// it waits (with exponential backoff up to 60s) and tries again. Exits when
// the server shuts down.
func (s *PeerServer) seedReconnectLoop(addr string) {
	backoff := 5 * time.Second
	const maxBackoff = 60 * time.Second
	for {
		if s.hasPeer(addr) {
			backoff = 5 * time.Second
			select {
			case <-s.quit:
				return
			case <-time.After(10 * time.Second):
				continue
			}
		}
		if err := s.ConnectPeer(addr); err != nil {
			log.Printf("[p2p] seed %s dial failed: %v (retry in %s)", addr, err, backoff)
			select {
			case <-s.quit:
				return
			case <-time.After(backoff):
			}
			if backoff < maxBackoff {
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
			}
			continue
		}
		backoff = 5 * time.Second
	}
}

// hasPeer returns true if a peer with the given address is currently connected.
func (s *PeerServer) hasPeer(addr string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.peers[addr]
	return ok
}

// BlockLocator builds a Bitcoin-style block locator list from the current chain tip.
// It includes exponentially fewer hashes as it goes back in history.
func (s *PeerServer) BlockLocator() [][32]byte {
	height := s.bc.BestHeight()
	var locator [][32]byte
	step := uint64(1)

	for h := height; ; {
		hash, err := s.bc.GetBlockHashAtHeight(h)
		if err != nil {
			break
		}
		locator = append(locator, hash)
		if h == 0 {
			break
		}
		if len(locator) >= 10 {
			step *= 2
		}
		if h < step {
			h = 0
		} else {
			h -= step
		}
	}

	return locator
}
