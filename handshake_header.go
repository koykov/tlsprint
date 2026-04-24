package tlsvector

import (
	"math"
)

type MessageType uint8

const (
	MessageTypeUnknown     MessageType = 0
	MessageTypeClientHello MessageType = 0x01
	MessageTypeServerHello MessageType = 0x02
)

func (mt MessageType) Raw() uint8 {
	return uint8(mt)
}

func (mt MessageType) String() string {
	if mt > MessageTypeServerHello {
		return mtyps[MessageTypeUnknown]
	}
	return mtyps[mt]
}

type MessageVersion uint16

func (mv MessageVersion) Raw() uint16 {
	return uint16(mv)
}

func (mv MessageVersion) String() string {
	lo, hi := byte(mv), byte(mv>>8)
	switch {
	case hi == 3 && lo == 0:
		return "SSL3.0"
	case hi == 3 && lo == 1:
		return "TLS1.0"
	case hi == 3 && lo == 2:
		return "TLS1.1"
	case hi == 3 && lo == 3:
		return "TLS1.2"
	case hi == 3 && lo == 4:
		return "TLS1.3"
	default:
		return "UNK"
	}
}

func (vec *vector) parseHandshakeHeader(off uint32) (_ uint32, err error) {
	var raw []byte
	if raw, off, err = vec.cut(off, 4); err != nil {
		return off, err
	}
	// Read message type byte.
	if vec.mtyp = MessageType(raw[0]); vec.mtyp == MessageTypeUnknown {
		return off, ErrNoHello
	}
	// Read message length.
	vec.mlen = uint32(raw[3]) | uint32(raw[2])<<8 | uint32(raw[1])<<16

	return off, err
}

var mtyps [math.MaxUint8]string

func init() {
	mtyps[MessageTypeUnknown] = "UNKNOWN"
	mtyps[MessageTypeClientHello] = "CLIENT_HELLO"
	mtyps[MessageTypeServerHello] = "SERVER_HELLO"
}
