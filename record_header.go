package tlsprint

import (
	"encoding/binary"
	"io"
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

func (vec *vector) parseRecordHeader(off uint32) (_ uint32, err error) {
	raw := vec.raw[off:]
	if len(raw) == 0 {
		return off, io.ErrUnexpectedEOF
	}
	if raw[0] != 0x16 {
		// Record header not found.
		vec.rtyp = RecordTypeUnknown
		return off, nil
	}

	// Byte at position is 0x16 - handshake type.
	vec.rtyp = RecordTypeHandshake
	off++
	// Read protocol version.
	if raw, off, err = vec.cut(off, 2); err != nil {
		return off, err
	}
	vec.rver = binary.LittleEndian.Uint16(raw)
	// Read handshake length.
	if raw, off, err = vec.cut(off, 2); err != nil {
		return off, err
	}
	vec.rlen, err = x2u16(raw)

	return off, err
}

var rtyps [math.MaxUint8]string

func init() {
	rtyps[RecordTypeUnknown] = "UNKNOWN"
	rtyps[RecordTypeHandshake] = "HANDSHAKE"
}
