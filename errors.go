package tlsvector

import "errors"

var (
	ErrNoHandshake       = errors.New(`given message data doesn't contain handshake message`)
	ErrNoHello           = errors.New(`given message data doesn't contain hello message`)
	ErrNoData            = errors.New("no data to parse provided")
	ErrTooShort          = errors.New("data is too short")
	ErrHexTooLong        = errors.New("hex data length exceeds 16 bytes")
	ErrHexBadByte        = errors.New("hex byte must be in range 0..F")
	ErrUnknownPacketType = errors.New("unknown packet type")
)
