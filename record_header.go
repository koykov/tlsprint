package tlsvector

import (
	"encoding/binary"
	"math"
)

type RecordType uint8

const (
	RecordTypeUnknown   RecordType = 0
	RecordTypeHandshake RecordType = 0x16
)

func (rt RecordType) String() string {
	return rtyps[rt]
}

type RecordVersion uint16

func (rv RecordVersion) Raw() uint16 {
	return uint16(rv)
}

func (rv RecordVersion) String() string {
	lo, hi := byte(rv), byte(rv>>8)
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

func (vec *vector) parseRecordHeader(off uint32) (_ uint32, err error) {
	var raw []byte
	if raw, off, err = vec.cut(off, 5); err != nil {
		return off, err
	}
	if raw[0] != 0x16 {
		// Record header not found.
		vec.rtyp = RecordTypeUnknown
		return off, ErrNoHandshake
	}

	// Byte at position is 0x16 - handshake type.
	vec.rtyp = RecordTypeHandshake
	// Read protocol version.
	vec.rver = RecordVersion(binary.BigEndian.Uint16(raw[1:3]))
	// Read handshake length.
	vec.rlen = binary.BigEndian.Uint16(raw[3:5])

	return off, err
}

var rtyps [math.MaxUint8]string

func init() {
	rtyps[RecordTypeUnknown] = "UNKNOWN"
	rtyps[RecordTypeHandshake] = "HANDSHAKE"
}
