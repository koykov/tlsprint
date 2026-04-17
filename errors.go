package tlsprint

import "errors"

var (
	ErrTooShort          = errors.New("data is too short")
	ErrUnknownPacketType = errors.New("unknown packet type")
)
