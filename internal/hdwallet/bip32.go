package hdwallet

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/computervirtualservices/malairte/internal/crypto"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// BIP32 version bytes (standard mainnet). The signer's ParseExtendedPubKey does
// not validate the version prefix, so a standard xpub round-trips into it
// unchanged. Using the standard prefixes also means the mnemonic+xpub are
// portable to other BIP32 tooling (e.g. the NBitcoin-based MLRT wallet).
var (
	versionXprv = [4]byte{0x04, 0x88, 0xAD, 0xE4} // xprv
	versionXpub = [4]byte{0x04, 0x88, 0xB2, 0x1E} // xpub
)

const hardened uint32 = 0x8000_0000

// ExtKey is a BIP32 extended key (private or public).
type ExtKey struct {
	Version   [4]byte
	Depth     byte
	ParentFP  [4]byte
	ChildNum  uint32
	ChainCode []byte // 32 bytes
	Key       []byte // private: 33 bytes (0x00 || 32-byte d); public: 33-byte compressed point
	IsPrivate bool
}

// NewMasterKey derives the BIP32 master extended PRIVATE key from a seed:
//
//	I = HMAC-SHA512(Key = "Bitcoin seed", Data = seed)
//	master priv key = IL, chain code = IR
func NewMasterKey(seed []byte) (*ExtKey, error) {
	I := hmacSHA512([]byte("Bitcoin seed"), seed)
	il, ir := I[:32], I[32:]

	var s secp256k1.ModNScalar
	if overflow := s.SetByteSlice(il); overflow || s.IsZero() {
		return nil, errors.New("invalid master key (IL ≥ n or zero); use a different seed")
	}

	k := &ExtKey{
		Version:   versionXprv,
		Depth:     0,
		ChildNum:  0,
		ChainCode: append([]byte(nil), ir...),
		Key:       append([]byte{0x00}, il...),
		IsPrivate: true,
	}
	return k, nil
}

// privScalar returns the private key as a secp256k1 scalar (private keys only).
func (k *ExtKey) privScalar() *secp256k1.ModNScalar {
	var s secp256k1.ModNScalar
	s.SetByteSlice(k.Key[1:]) // strip the 0x00 prefix
	return &s
}

// pubBytes returns the 33-byte compressed public key for this extended key.
func (k *ExtKey) pubBytes() []byte {
	if !k.IsPrivate {
		return k.Key
	}
	priv := secp256k1.PrivKeyFromBytes(k.Key[1:])
	return priv.PubKey().SerializeCompressed()
}

// fingerprint is the first 4 bytes of Hash160(pubkey), used as the child's
// parent fingerprint.
func (k *ExtKey) fingerprint() [4]byte {
	h := crypto.Hash160(k.pubBytes())
	var fp [4]byte
	copy(fp[:], h[:4])
	return fp
}

// CKDpriv derives a child PRIVATE key (BIP32). Supports hardened indices
// (index ≥ 2^31). Private keys only.
func (k *ExtKey) CKDpriv(index uint32) (*ExtKey, error) {
	if !k.IsPrivate {
		return nil, errors.New("CKDpriv requires a private extended key")
	}

	data := make([]byte, 37)
	if index >= hardened {
		// Hardened: 0x00 || ser256(k_par) || ser32(i)
		copy(data[1:33], k.Key[1:])
	} else {
		// Normal: serP(point(k_par)) || ser32(i)
		copy(data[0:33], k.pubBytes())
	}
	binary.BigEndian.PutUint32(data[33:37], index)

	I := hmacSHA512(k.ChainCode, data)
	il, ir := I[:32], I[32:]

	var ilScalar secp256k1.ModNScalar
	if overflow := ilScalar.SetByteSlice(il); overflow || ilScalar.IsZero() {
		return nil, fmt.Errorf("invalid child (IL ≥ n or zero) at index %d; try the next index", index)
	}

	// child priv = (IL + parent priv) mod n
	childScalar := ilScalar.Add(k.privScalar())
	if childScalar.IsZero() {
		return nil, fmt.Errorf("invalid child (resulting key zero) at index %d; try the next index", index)
	}
	childBytes := childScalar.Bytes()

	child := &ExtKey{
		Version:   versionXprv,
		Depth:     k.Depth + 1,
		ParentFP:  k.fingerprint(),
		ChildNum:  index,
		ChainCode: append([]byte(nil), ir...),
		Key:       append([]byte{0x00}, childBytes[:]...),
		IsPrivate: true,
	}
	return child, nil
}

// Derive applies a sequence of child indices in order (use the H helper for
// hardened levels).
func (k *ExtKey) Derive(path ...uint32) (*ExtKey, error) {
	cur := k
	for _, idx := range path {
		next, err := cur.CKDpriv(idx)
		if err != nil {
			return nil, err
		}
		cur = next
	}
	return cur, nil
}

// Neuter returns the public extended key corresponding to a private one.
func (k *ExtKey) Neuter() *ExtKey {
	if !k.IsPrivate {
		return k
	}
	return &ExtKey{
		Version:   versionXpub,
		Depth:     k.Depth,
		ParentFP:  k.ParentFP,
		ChildNum:  k.ChildNum,
		ChainCode: append([]byte(nil), k.ChainCode...),
		Key:       k.pubBytes(),
		IsPrivate: false,
	}
}

// String serializes the extended key as a Base58Check string (xprv/xpub).
//
// The 78-byte body is version(4) || depth(1) || parentFP(4) || childNum(4) ||
// chainCode(32) || key(33); Base58Check appends a 4-byte double-SHA256 checksum.
// We reuse the node's audited Base58Check encoder (it prepends body[0] as the
// "version" byte and treats the rest as payload — identical to standard
// extended-key serialization).
func (k *ExtKey) String() (string, error) {
	body := make([]byte, 0, 78)
	body = append(body, k.Version[:]...)
	body = append(body, k.Depth)
	body = append(body, k.ParentFP[:]...)
	var cn [4]byte
	binary.BigEndian.PutUint32(cn[:], k.ChildNum)
	body = append(body, cn[:]...)
	body = append(body, k.ChainCode...)
	body = append(body, k.Key...)

	if len(body) != 78 {
		return "", fmt.Errorf("extended key body must be 78 bytes, got %d", len(body))
	}
	return crypto.Base58CheckEncode(body[0], body[1:])
}

// H marks a child index as hardened (i.e. i + 2^31).
func H(i uint32) uint32 { return i + hardened }
