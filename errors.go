package tlsprint

import "errors"

var (
	ErrNoData            = errors.New("no data to parse provided")
	ErrTooShort          = errors.New("data is too short")
	ErrHexTooLong        = errors.New("hex data length exceeds 16 bytes")
	ErrUnknownPacketType = errors.New("unknown packet type")
)
