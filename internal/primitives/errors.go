package primitives

import "errors"

var (
	errInvalidVarInt = errors.New("invalid varint encoding")
	errTooShort      = errors.New("data too short for deserialization")
)
