package tlsprint

import (
	"io"
	"math"
)

type MessageType uint8

const (
	MessageTypeUnknown     MessageType = 0
	MessageTypeClientHello MessageType = 0x01
	MessageTypeServerHello MessageType = 0x02
)

func (mt MessageType) String() string {
	if mt > MessageTypeServerHello {
		return mtyps[MessageTypeUnknown]
	}
	return mtyps[mt]
}

func (vec *vector) parseHandshakeHeader(off uint32) (_ uint32, err error) {
	raw := vec.raw[off:]
	if len(raw) == 0 {
		return off, io.ErrUnexpectedEOF
	}
	// Read message type byte.
	vec.mtyp = MessageType(raw[0])
	off++
	// Read message length.
	if raw, off, err = vec.cut(off, 3); err != nil {
		return off, err
	}
	vec.mlen = uint32(raw[0]) | uint32(raw[1])<<8 | uint32(raw[2])<<16

	return off, err
}

var mtyps [math.MaxUint8]string

func init() {
	mtyps[MessageTypeUnknown] = "UNKNOWN"
	mtyps[MessageTypeClientHello] = "CLIENT_HELLO"
	mtyps[MessageTypeServerHello] = "SERVER_HELLO"
}
