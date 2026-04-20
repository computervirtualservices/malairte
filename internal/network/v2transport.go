// Package network — v2 encrypted peer transport.
//
// Implements an encrypted, authenticated, forward-secret peer-to-peer transport
// derived from BIP-324. The handshake uses ElligatorSwift-encoded secp256k1
// public keys (64-byte uniformly random byte strings), so a passive observer
// cannot cheaply distinguish the handshake from random noise. After the
// handshake, every packet is:
//
//   [3-byte encrypted length LE] [payload] [16-byte Poly1305 tag]
//
// The length is masked with a ChaCha20 keystream derived from a dedicated
// subkey; the payload is sealed with ChaCha20-Poly1305 under a separate
// subkey. Nonces are 12-byte counter-based (unique per session direction).
//
// DELIBERATE DEVIATIONS FROM BIP-324:
//
//   - No FSChaCha20: this implementation uses plain ChaCha20 for the length
//     field. Full BIP-324 rekeys the length cipher after every packet for
//     forward secrecy against a single-packet key compromise. We accept a
//     session-wide compromise window in exchange for simpler framing.
//   - No garbage-terminator handshake extension: BIP-324's optional garbage
//     bytes after the pubkey make handshake fingerprinting harder. Adding
//     them is a pure-additive upgrade; skipped for now.
//   - No automatic rekeying: sessions must be closed and re-established if
//     they approach 2^32 packets (ChaCha20-Poly1305's nonce-reuse boundary).
//
// These gaps do NOT affect confidentiality or integrity of any single packet;
// they only affect long-term traffic-analysis resistance and session
// longevity. All three are additive future work.
package network

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/btcec/v2/ellswift"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// V2MaxPacketPayload is the largest plaintext payload permitted in one packet.
// The 3-byte length field allows up to ~16 MB; we cap at 4 MB to match
// MaxBlockWeight (a block is the biggest payload we'll ship).
const V2MaxPacketPayload = 4 * 1024 * 1024

// ellswiftPubKeySize is the on-wire size of an ElligatorSwift-encoded secp256k1
// public key. Two 32-byte field elements concatenated — looks uniformly
// random to an observer.
const ellswiftPubKeySize = 64

// v2InfoLabel is mixed into HKDF so the session keys cannot collide with
// subkeys from any other Malairt crypto context.
const v2InfoLabel = "malairt/v2-transport/v1"

// Session represents an established v2 transport. It is NOT safe for
// concurrent use by multiple readers or writers — callers should serialise
// access (matching the existing Peer goroutine pattern of one reader + one
// writer).
type Session struct {
	sendContent, recvContent *packetCipherImpl
	sendLength, recvLength   *lengthCipher
}

// packetCipherImpl wraps a ChaCha20-Poly1305 AEAD with a packet counter
// that becomes the 12-byte nonce.
type packetCipherImpl struct {
	aead    interface {
		Seal(dst, nonce, plaintext, additionalData []byte) []byte
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	}
	counter uint64
}

func (p *packetCipherImpl) seal(plaintext []byte) []byte {
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], p.counter)
	p.counter++
	return p.aead.Seal(nil, nonce[:], plaintext, nil)
}

func (p *packetCipherImpl) open(ciphertext []byte) ([]byte, error) {
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], p.counter)
	p.counter++
	return p.aead.Open(nil, nonce[:], ciphertext, nil)
}

// lengthCipher generates a 3-byte keystream mask for each packet's length
// field, using a fresh ChaCha20 block per packet (counter = packet number).
type lengthCipher struct {
	key     [32]byte
	counter uint64
}

func (l *lengthCipher) mask(out []byte) error {
	if len(out) != 3 {
		return errors.New("v2transport: length mask must be 3 bytes")
	}
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], l.counter)
	l.counter++
	cipher, err := chacha20.NewUnauthenticatedCipher(l.key[:], nonce[:])
	if err != nil {
		return err
	}
	var buf [3]byte
	cipher.XORKeyStream(buf[:], buf[:]) // XOR zeros → first 3 keystream bytes
	for i := range out {
		out[i] ^= buf[i]
	}
	return nil
}

// InitiateV2 performs the handshake as the connecting party and returns a
// ready-to-use Session. The caller provides a full-duplex transport (a TCP
// net.Conn, net.Pipe, etc.) — both sides must agree on initiator/responder
// roles before calling this function, e.g. the accept side calls AcceptV2.
func InitiateV2(rw io.ReadWriter) (*Session, error) {
	return performHandshake(rw, true)
}

// AcceptV2 performs the handshake as the accepting party.
func AcceptV2(rw io.ReadWriter) (*Session, error) {
	return performHandshake(rw, false)
}

func performHandshake(rw io.ReadWriter, initiating bool) (*Session, error) {
	priv, ourPub, err := ellswift.EllswiftCreate()
	if err != nil {
		return nil, fmt.Errorf("v2transport: ellswift keygen: %w", err)
	}

	// Initiator writes first, then reads. Responder reads first, then writes.
	// Writing our pubkey before reading theirs is fine because ellswift-
	// encoded bytes look random — a passive observer cannot infer roles.
	var theirPub [ellswiftPubKeySize]byte
	if initiating {
		if _, err := rw.Write(ourPub[:]); err != nil {
			return nil, fmt.Errorf("v2transport: send pubkey: %w", err)
		}
		if _, err := io.ReadFull(rw, theirPub[:]); err != nil {
			return nil, fmt.Errorf("v2transport: recv pubkey: %w", err)
		}
	} else {
		if _, err := io.ReadFull(rw, theirPub[:]); err != nil {
			return nil, fmt.Errorf("v2transport: recv pubkey: %w", err)
		}
		if _, err := rw.Write(ourPub[:]); err != nil {
			return nil, fmt.Errorf("v2transport: send pubkey: %w", err)
		}
	}

	shared, err := ellswift.V2Ecdh(priv, theirPub, ourPub, initiating)
	if err != nil {
		return nil, fmt.Errorf("v2transport: V2Ecdh: %w", err)
	}
	return deriveSession(shared[:], initiating)
}

// deriveSession runs HKDF-SHA256 over the 32-byte shared secret to produce
// four 32-byte subkeys (2 × content, 2 × length), then wires up AEAD + length
// ciphers per role. Role assignment ensures the two peers have mirrored
// sendKey/recvKey — initiator's sendContent == responder's recvContent and
// vice versa.
func deriveSession(shared []byte, initiating bool) (*Session, error) {
	// We need 4 × 32 = 128 bytes of output keying material.
	okm := make([]byte, 128)
	reader := hkdf.New(sha256.New, shared, nil, []byte(v2InfoLabel))
	if _, err := io.ReadFull(reader, okm); err != nil {
		return nil, fmt.Errorf("v2transport: hkdf: %w", err)
	}
	var (
		a2bContent [32]byte // initiator → responder, content key
		b2aContent [32]byte // responder → initiator, content key
		a2bLength  [32]byte // initiator → responder, length key
		b2aLength  [32]byte // responder → initiator, length key
	)
	copy(a2bContent[:], okm[0:32])
	copy(b2aContent[:], okm[32:64])
	copy(a2bLength[:], okm[64:96])
	copy(b2aLength[:], okm[96:128])

	newAEAD := func(k [32]byte) (*packetCipherImpl, error) {
		a, err := chacha20poly1305.New(k[:])
		if err != nil {
			return nil, err
		}
		return &packetCipherImpl{aead: a}, nil
	}

	sess := &Session{}
	var err error
	if initiating {
		if sess.sendContent, err = newAEAD(a2bContent); err != nil {
			return nil, err
		}
		if sess.recvContent, err = newAEAD(b2aContent); err != nil {
			return nil, err
		}
		sess.sendLength = &lengthCipher{key: a2bLength}
		sess.recvLength = &lengthCipher{key: b2aLength}
	} else {
		if sess.sendContent, err = newAEAD(b2aContent); err != nil {
			return nil, err
		}
		if sess.recvContent, err = newAEAD(a2bContent); err != nil {
			return nil, err
		}
		sess.sendLength = &lengthCipher{key: b2aLength}
		sess.recvLength = &lengthCipher{key: a2bLength}
	}
	return sess, nil
}

// WritePacket encrypts payload and writes the framed packet to w.
// Not safe for concurrent use — callers must serialise writes.
func (s *Session) WritePacket(w io.Writer, payload []byte) error {
	if len(payload) > V2MaxPacketPayload {
		return fmt.Errorf("v2transport: payload %d exceeds max %d", len(payload), V2MaxPacketPayload)
	}
	ciphertext := s.sendContent.seal(payload)

	// 3-byte LE length of the ciphertext (which includes the 16-byte tag).
	var lenBytes [3]byte
	lenBytes[0] = byte(len(ciphertext))
	lenBytes[1] = byte(len(ciphertext) >> 8)
	lenBytes[2] = byte(len(ciphertext) >> 16)
	if err := s.sendLength.mask(lenBytes[:]); err != nil {
		return err
	}
	if _, err := w.Write(lenBytes[:]); err != nil {
		return fmt.Errorf("v2transport: write length: %w", err)
	}
	if _, err := w.Write(ciphertext); err != nil {
		return fmt.Errorf("v2transport: write ciphertext: %w", err)
	}
	return nil
}

// ReadPacket reads one framed packet from r and returns the decrypted payload.
// Returns an error if the MAC fails — callers MUST drop the session on the
// first auth failure (any ciphertext the attacker can influence is suspect).
func (s *Session) ReadPacket(r io.Reader) ([]byte, error) {
	var lenBytes [3]byte
	if _, err := io.ReadFull(r, lenBytes[:]); err != nil {
		return nil, fmt.Errorf("v2transport: read length: %w", err)
	}
	if err := s.recvLength.mask(lenBytes[:]); err != nil {
		return nil, err
	}
	n := int(lenBytes[0]) | int(lenBytes[1])<<8 | int(lenBytes[2])<<16
	if n < chacha20poly1305.Overhead {
		return nil, fmt.Errorf("v2transport: ciphertext length %d < tag size %d", n, chacha20poly1305.Overhead)
	}
	if n > V2MaxPacketPayload+chacha20poly1305.Overhead {
		return nil, fmt.Errorf("v2transport: ciphertext length %d > max", n)
	}
	ciphertext := make([]byte, n)
	if _, err := io.ReadFull(r, ciphertext); err != nil {
		return nil, fmt.Errorf("v2transport: read ciphertext: %w", err)
	}
	plaintext, err := s.recvContent.open(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("v2transport: authentication failed: %w", err)
	}
	return plaintext, nil
}

