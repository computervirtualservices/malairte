package network

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/malairt/malairt/internal/chain"
)

// PeerMessage wraps a decoded message with its source peer.
type PeerMessage struct {
	Peer    *Peer
	Message *NetMessage
}

// Peer represents a single P2P connection, either inbound or outbound.
// All public methods are safe for concurrent use.
type Peer struct {
	conn        net.Conn
	addr        string
	inbound     bool
	version     uint32
	services    uint64
	userAgent   string
	startHeight int32
	outbound    chan *NetMessage
	quit        chan struct{}
	quitOnce    sync.Once
	params      *chain.ChainParams
}

// NewPeer wraps a net.Conn into a Peer.
// params is used to validate magic bytes on received messages.
func NewPeer(conn net.Conn, params *chain.ChainParams, inbound bool) *Peer {
	return &Peer{
		conn:     conn,
		addr:     conn.RemoteAddr().String(),
		inbound:  inbound,
		outbound: make(chan *NetMessage, 64),
		quit:     make(chan struct{}),
		params:   params,
	}
}

// Start launches the send and receive goroutines for this peer.
// msgCh receives all decoded messages from this peer.
// Returns a channel that is closed when the peer disconnects.
func (p *Peer) Start(msgCh chan<- PeerMessage) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.readLoop(msgCh)
	}()
	go p.writeLoop()
	return done
}

// Send queues a message to be sent to this peer.
// Drops the message if the peer's send queue is full.
func (p *Peer) Send(msg *NetMessage) {
	select {
	case p.outbound <- msg:
	case <-p.quit:
	default:
		log.Printf("[peer %s] send queue full, dropping %s message", p.addr, msg.Command)
	}
}

// Disconnect closes the peer connection and signals all goroutines to stop.
func (p *Peer) Disconnect() {
	p.quitOnce.Do(func() {
		close(p.quit)
		p.conn.Close()
	})
}

// Addr returns the remote address of this peer.
func (p *Peer) Addr() string {
	return p.addr
}

// IsInbound returns true if this peer connected to us (we didn't initiate the connection).
func (p *Peer) IsInbound() bool {
	return p.inbound
}

// UserAgent returns the peer's self-reported user agent string.
func (p *Peer) UserAgent() string {
	return p.userAgent
}

// StartHeight returns the peer's self-reported chain height at connection time.
func (p *Peer) StartHeight() int32 {
	return p.startHeight
}

// SetVersion stores the peer's negotiated version information.
func (p *Peer) SetVersion(version uint32, services uint64, userAgent string, startHeight int32) {
	p.version = version
	p.services = services
	p.userAgent = userAgent
	p.startHeight = startHeight
}

// readLoop continuously reads messages from the connection and sends them to msgCh.
func (p *Peer) readLoop(msgCh chan<- PeerMessage) {
	defer p.Disconnect()

	magic := p.params.MagicBytes()
	p.conn.SetDeadline(time.Time{}) // no global deadline; use per-read timeouts

	for {
		select {
		case <-p.quit:
			return
		default:
		}

		// Set a read deadline to detect dead connections
		p.conn.SetReadDeadline(time.Now().Add(5 * time.Minute))

		msg, err := DecodeMessage(p.conn, magic)
		if err != nil {
			select {
			case <-p.quit:
				// Expected disconnection
			default:
				log.Printf("[peer %s] read error: %v", p.addr, err)
			}
			return
		}

		select {
		case msgCh <- PeerMessage{Peer: p, Message: msg}:
		case <-p.quit:
			return
		}
	}
}

// writeLoop continuously writes queued messages to the connection.
func (p *Peer) writeLoop() {
	magic := p.params.MagicBytes()

	for {
		select {
		case msg := <-p.outbound:
			p.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
			data := EncodeMessage(magic, msg.Command, msg.Payload)
			if _, err := p.conn.Write(data); err != nil {
				select {
				case <-p.quit:
				default:
					log.Printf("[peer %s] write error: %v", p.addr, err)
				}
				p.Disconnect()
				return
			}
		case <-p.quit:
			return
		}
	}
}

// SendVersion sends a version message to initiate the handshake.
func (p *Peer) SendVersion(ourVersion uint32, services uint64, userAgent string, startHeight int32) {
	msg := &VersionMsg{
		Version:     ourVersion,
		Services:    services,
		Timestamp:   time.Now().Unix(),
		AddrRecv:    p.addr,
		AddrFrom:    "",
		Nonce:       0,
		UserAgent:   userAgent,
		StartHeight: startHeight,
	}
	p.Send(&NetMessage{Command: CmdVersion, Payload: msg.Encode()})
}

// SendVerAck sends a verack message in response to a version message.
func (p *Peer) SendVerAck() {
	p.Send(&NetMessage{Command: CmdVerAck, Payload: []byte{}})
}

// SendPing sends a ping with the given nonce.
func (p *Peer) SendPing(nonce uint64) {
	ping := &PingMsg{Nonce: nonce}
	p.Send(&NetMessage{Command: CmdPing, Payload: ping.Encode()})
}

// SendInv sends an inventory message announcing a new block or transaction.
func (p *Peer) SendInv(items []InvVect) {
	inv := &InvMsg{Items: items}
	p.Send(&NetMessage{Command: CmdInv, Payload: inv.Encode()})
}

// String returns a human-readable description of the peer.
func (p *Peer) String() string {
	direction := "outbound"
	if p.inbound {
		direction = "inbound"
	}
	return fmt.Sprintf("Peer(%s, %s, v%d)", p.addr, direction, p.version)
}
