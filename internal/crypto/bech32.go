package crypto

import (
	"errors"
	"fmt"
	"strings"
)

// Bech32 (BIP-173) and Bech32m (BIP-350) encode a byte string together with a
// human-readable prefix (HRP) under a BCH-based checksum. The two variants
// differ only in a single checksum constant: bech32 uses 1, bech32m uses
// 0x2BC830A3. SegWit v0 addresses use bech32; SegWit v1+ (taproot and
// beyond) use bech32m — mixing them up silently produces look-alike strings
// that decode only under the wrong rules, which is why BIP-350 ships its
// own constant.

const (
	bech32Const  uint32 = 1
	bech32mConst uint32 = 0x2bc830a3

	// SpecBech32 marks a string that decoded cleanly under the BIP-173
	// (witness v0) rules. SpecBech32m marks BIP-350 (witness v1+).
	SpecBech32  = 0
	SpecBech32m = 1
)

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

// bech32CharsetRev[c] = index in bech32Charset, or -1 if not a bech32 char.
var bech32CharsetRev = func() [128]int8 {
	var r [128]int8
	for i := range r {
		r[i] = -1
	}
	for i, c := range bech32Charset {
		r[c] = int8(i)
	}
	return r
}()

// bech32Polymod runs the BCH polymod over the expanded data values.
func bech32Polymod(values []byte) uint32 {
	gen := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = ((chk & 0x1ffffff) << 5) ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (top>>i)&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

// bech32HRPExpand expands hrp into the 2n+1-element array required by the
// bech32 checksum algorithm.
func bech32HRPExpand(hrp string) []byte {
	n := len(hrp)
	out := make([]byte, 2*n+1)
	for i := 0; i < n; i++ {
		out[i] = hrp[i] >> 5
	}
	out[n] = 0
	for i := 0; i < n; i++ {
		out[n+1+i] = hrp[i] & 31
	}
	return out
}

// bech32VerifyChecksum returns the spec (SpecBech32 or SpecBech32m) that the
// string validates under, or -1 if neither matches.
func bech32VerifyChecksum(hrp string, data []byte) int {
	values := append(bech32HRPExpand(hrp), data...)
	switch bech32Polymod(values) {
	case bech32Const:
		return SpecBech32
	case bech32mConst:
		return SpecBech32m
	default:
		return -1
	}
}

func bech32CreateChecksum(hrp string, data []byte, spec int) []byte {
	var c uint32
	if spec == SpecBech32m {
		c = bech32mConst
	} else {
		c = bech32Const
	}
	values := append(bech32HRPExpand(hrp), data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	polymod := bech32Polymod(values) ^ c
	out := make([]byte, 6)
	for i := 0; i < 6; i++ {
		out[i] = byte((polymod >> uint(5*(5-i))) & 31)
	}
	return out
}

// bech32Encode produces a bech32(m) string from the HRP and 5-bit data values.
// spec must be SpecBech32 or SpecBech32m.
func bech32Encode(hrp string, data []byte, spec int) (string, error) {
	if !validHRP(hrp) {
		return "", fmt.Errorf("bech32: invalid hrp %q", hrp)
	}
	combined := append(append([]byte{}, data...), bech32CreateChecksum(hrp, data, spec)...)
	var b strings.Builder
	b.WriteString(hrp)
	b.WriteByte('1')
	for _, v := range combined {
		if int(v) >= len(bech32Charset) {
			return "", fmt.Errorf("bech32: 5-bit value out of range: %d", v)
		}
		b.WriteByte(bech32Charset[v])
	}
	return b.String(), nil
}

// bech32Decode splits a bech32(m) string into its HRP, 5-bit data values, and
// the spec under which the checksum validates. Returns an error if the string
// is malformed or the checksum does not validate under either spec.
//
// BIP-173 specified a 90-char max for SegWit compatibility; BIP-352 silent
// payment addresses are ~118 chars and are explicitly exempt. We enforce a
// soft upper bound of 1023 bytes (matching Bitcoin Core's practical limit)
// and leave callers that want tighter checks (e.g. DecodeSegWitAddress) to
// enforce their own payload length constraints.
func bech32Decode(s string) (hrp string, data []byte, spec int, err error) {
	if len(s) < 8 || len(s) > 1023 {
		return "", nil, 0, fmt.Errorf("bech32: length %d out of range [8,1023]", len(s))
	}
	// No mixed case
	lower := strings.ToLower(s)
	upper := strings.ToUpper(s)
	if s != lower && s != upper {
		return "", nil, 0, errors.New("bech32: mixed case")
	}
	s = lower
	pos := strings.LastIndexByte(s, '1')
	if pos < 1 || pos+7 > len(s) {
		return "", nil, 0, errors.New("bech32: invalid separator position")
	}
	hrp = s[:pos]
	if !validHRP(hrp) {
		return "", nil, 0, fmt.Errorf("bech32: invalid hrp %q", hrp)
	}
	data = make([]byte, 0, len(s)-pos-1)
	for i := pos + 1; i < len(s); i++ {
		c := s[i]
		if c >= 128 || bech32CharsetRev[c] < 0 {
			return "", nil, 0, fmt.Errorf("bech32: invalid character %q", c)
		}
		data = append(data, byte(bech32CharsetRev[c]))
	}
	spec = bech32VerifyChecksum(hrp, data)
	if spec < 0 {
		return "", nil, 0, errors.New("bech32: invalid checksum")
	}
	return hrp, data[:len(data)-6], spec, nil
}

func validHRP(hrp string) bool {
	if len(hrp) == 0 || len(hrp) > 83 {
		return false
	}
	for i := 0; i < len(hrp); i++ {
		c := hrp[i]
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}

// convertBits regroups a byte sequence from fromBits-bit groups into
// toBits-bit groups, padding the final group if pad is true.
func convertBits(data []byte, fromBits, toBits uint, pad bool) ([]byte, error) {
	acc := uint32(0)
	bits := uint(0)
	out := []byte{}
	maxv := uint32((1 << toBits) - 1)
	maxAcc := uint32((1 << (fromBits + toBits - 1)) - 1)
	for _, v := range data {
		if uint32(v)>>fromBits != 0 {
			return nil, fmt.Errorf("bech32: value %d overflows %d-bit group", v, fromBits)
		}
		acc = ((acc << fromBits) | uint32(v)) & maxAcc
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			out = append(out, byte((acc>>bits)&maxv))
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, byte((acc<<(toBits-bits))&maxv))
		}
	} else if bits >= fromBits || ((acc<<(toBits-bits))&maxv) != 0 {
		return nil, errors.New("bech32: non-zero padding in convertBits")
	}
	return out, nil
}

// EncodeSegWitAddress encodes a SegWit output (version + witness program) as a
// bech32/bech32m address under the given HRP. version 0 uses bech32;
// versions 1–16 use bech32m. program must be 2–40 bytes; for v0 it is 20
// (P2WPKH) or 32 (P2WSH); for v1 taproot it is 32.
func EncodeSegWitAddress(hrp string, version byte, program []byte) (string, error) {
	if version > 16 {
		return "", fmt.Errorf("segwit: invalid witness version %d", version)
	}
	if len(program) < 2 || len(program) > 40 {
		return "", fmt.Errorf("segwit: program length %d out of range [2,40]", len(program))
	}
	if version == 0 && len(program) != 20 && len(program) != 32 {
		return "", fmt.Errorf("segwit: v0 program must be 20 or 32 bytes, got %d", len(program))
	}
	data5, err := convertBits(program, 8, 5, true)
	if err != nil {
		return "", err
	}
	data := append([]byte{version}, data5...)
	spec := SpecBech32m
	if version == 0 {
		spec = SpecBech32
	}
	return bech32Encode(hrp, data, spec)
}

// DecodeSegWitAddress parses a bech32/bech32m SegWit address and returns the
// HRP, witness version, and program bytes. Enforces the BIP-173/350 rule that
// v0 uses bech32 and v1+ uses bech32m.
func DecodeSegWitAddress(addr string) (hrp string, version byte, program []byte, err error) {
	hrp, data, spec, err := bech32Decode(addr)
	if err != nil {
		return "", 0, nil, err
	}
	if len(data) < 1 {
		return "", 0, nil, errors.New("segwit: empty data")
	}
	version = data[0]
	if version > 16 {
		return "", 0, nil, fmt.Errorf("segwit: invalid witness version %d", version)
	}
	if version == 0 && spec != SpecBech32 {
		return "", 0, nil, errors.New("segwit: v0 address must use bech32, not bech32m")
	}
	if version > 0 && spec != SpecBech32m {
		return "", 0, nil, errors.New("segwit: v1+ address must use bech32m, not bech32")
	}
	program, err = convertBits(data[1:], 5, 8, false)
	if err != nil {
		return "", 0, nil, err
	}
	if len(program) < 2 || len(program) > 40 {
		return "", 0, nil, fmt.Errorf("segwit: program length %d out of range", len(program))
	}
	if version == 0 && len(program) != 20 && len(program) != 32 {
		return "", 0, nil, fmt.Errorf("segwit: v0 program must be 20 or 32 bytes, got %d", len(program))
	}
	return hrp, version, program, nil
}
