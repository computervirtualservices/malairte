package network

import (
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
		params:   params,
		peers:    make(map[string]*Peer),
		msgCh:    make(chan PeerMessage, 256),
		quit:     make(chan struct{}),
		maxPeers: defaultMaxPeers,
	}
}

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
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	peer := NewPeer(conn, s.params, false)
	s.addPeer(peer)

	done := peer.Start(s.msgCh)
	go func() {
		<-done
		s.removePeer(peer.Addr())
		log.Printf("[p2p] peer %s disconnected", peer.Addr())
	}()

	// Initiate version handshake
	peer.SendVersion(protocolVersion, 0, userAgent, int32(s.bc.BestHeight()))
	log.Printf("[p2p] connected to outbound peer %s", addr)
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
		s.addPeer(peer)

		done := peer.Start(s.msgCh)
		go func(p *Peer) {
			<-done
			s.removePeer(p.Addr())
			log.Printf("[p2p] inbound peer %s disconnected", p.Addr())
		}(peer)

		log.Printf("[p2p] accepted inbound peer %s", conn.RemoteAddr())
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
	if err := s.pool.Add(txMsg.Tx); err != nil {
		return // duplicate or invalid
	}
	txid := txMsg.Tx.TxID()
	log.Printf("[p2p] accepted tx %x from %s", txid, peer.Addr())
	inv := []InvVect{{Type: InvTypeTx, Hash: txid}}
	s.broadcastExcept(CmdInv, (&InvMsg{Items: inv}).Encode(), peer.Addr())
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
func (s *PeerServer) ConnectSeeds(seeds []string) {
	for _, seed := range seeds {
		go s.seedReconnectLoop(seed)
	}
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
