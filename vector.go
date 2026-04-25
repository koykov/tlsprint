package tlsvector

import (
	"fmt"
	"io"

	"github.com/koykov/byteconv"
)

type Interface interface {
	fmt.Stringer
	Parse(p []byte) error
	ParseString(s string) error
	Reset()

	RecordType() RecordType
	RecordLegacyVersion() RecordVersion
	RecordLength() uint16

	MessageType() MessageType
	MessageLength() uint32
	LegacyVersion() MessageVersion
	Random() []byte
	SessionID() []byte
	CipherSuites() []CipherSuite
	CompressionMethod() uint8
	Extensions() []Extension
}

type vector struct {
	raw []byte
	buf []byte

	rtyp RecordType    // record type (always handshake)
	rver RecordVersion // record version (legacy)
	rlen uint16        // record length (including handshake header)

	mtyp MessageType    // message type
	mlen uint32         // message length
	mver MessageVersion // TLS version (legacy)
	rand []byte         // client random
	sid  []byte         // session ID
	chps []CipherSuite  // cipher suites
	cmpl uint8          // compression method
	cmps uint8          // compression method
	ext  []Extension    // extensions
}

func New() Interface {
	return &vector{}
}

func (vec *vector) RecordType() RecordType {
	return vec.rtyp
}

func (vec *vector) RecordLegacyVersion() RecordVersion {
	return vec.rver
}

func (vec *vector) RecordLength() uint16 {
	return vec.rlen
}

func (vec *vector) MessageType() MessageType {
	return vec.mtyp
}

func (vec *vector) MessageLength() uint32 {
	return vec.mlen
}

func (vec *vector) LegacyVersion() MessageVersion {
	return vec.mver
}

func (vec *vector) Random() []byte {
	return vec.rand
}

func (vec *vector) SessionID() []byte {
	return vec.sid
}

func (vec *vector) CipherSuites() []CipherSuite {
	return vec.chps
}

func (vec *vector) CompressionMethod() uint8 {
	return vec.cmps
}

func (vec *vector) Extensions() []Extension {
	return vec.ext
}

func (vec *vector) String() string {
	vec.buf = vec.buf[:0]
	vec.buf = append(vec.buf, "Record:\n"...)

	vec.buf = fmt.Appendf(vec.buf, "\tType: %s (%d)\n", vec.rtyp.String(), vec.rtyp)
	vec.buf = fmt.Appendf(vec.buf, "\tLegacy version: %s (0x%04X)\n", vec.rver.String(), vec.rver.Raw())
	vec.buf = fmt.Appendf(vec.buf, "\tLength: %d\n", vec.rlen)

	vec.buf = append(vec.buf, "Handshake:\n"...)
	vec.buf = fmt.Appendf(vec.buf, "\tType: %s (0x%02X)\n", vec.mtyp.String(), vec.mtyp.Raw())
	vec.buf = fmt.Appendf(vec.buf, "\tLength: %d\n", vec.mlen)
	vec.buf = fmt.Appendf(vec.buf, "\tLegacy version: %s (0x%04X)\n", vec.mver.String(), vec.mver.Raw())
	vec.buf = fmt.Appendf(vec.buf, "\tRandom: %X\n", vec.rand)
	vec.buf = fmt.Appendf(vec.buf, "\tSession ID Length: %d\n", len(vec.sid))
	if len(vec.sid) > 0 {
		vec.buf = fmt.Appendf(vec.buf, "\tSession ID: %X\n", vec.sid)
	} else {
		vec.buf = append(vec.buf, "\tSession ID: N/D\n"...)
	}

	if len(vec.chps) > 0 {
		vec.buf = append(vec.buf, "\tCipher Suites:\n"...)
		for i := 0; i < len(vec.chps); i++ {
			vec.buf = fmt.Appendf(vec.buf, "\t\t%s (0x%02X)\n", vec.chps[i].String(), vec.chps[i].Raw())
		}
	} else {
		vec.buf = append(vec.buf, "\tCipher Suites: N/D\n"...)
	}

	vec.buf = fmt.Appendf(vec.buf, "\tCompression Method Length: %d\n", vec.cmpl)
	if vec.cmps == 0 {
		vec.buf = append(vec.buf, "\tCompression Method: NULL (0)\n"...)
	} else {
		vec.buf = fmt.Appendf(vec.buf, "\tCompression Method: %02X\n", vec.cmps)
	}

	if len(vec.ext) > 0 {
		vec.buf = append(vec.buf, "\tExtensions:\n"...)
		for i := 0; i < len(vec.ext); i++ {
			e := &vec.ext[i]
			vec.buf = fmt.Appendf(vec.buf, "\t\t%s (0x%04X)\n", e.Data, e.Type.Raw())
		}
	} else {
		vec.buf = append(vec.buf, "\tExtensions: N/D\n"...)
	}

	return byteconv.B2S(vec.buf)
}

func (vec *vector) Reset() {
	vec.raw = vec.raw[:0]
	vec.buf = vec.buf[:0]

	vec.rtyp = RecordTypeUnknown
	vec.rver = 0
	vec.rlen = 0

	vec.mtyp = MessageTypeUnknown
	vec.mlen = 0
	vec.mver = 0
	vec.rand = vec.rand[:0]
	vec.sid = vec.sid[:0]
	vec.chps = vec.chps[:0]
	vec.cmpl = 0
	vec.cmps = 0
	vec.ext = vec.ext[:0]
}

func (vec *vector) cut(off, delta uint32) ([]byte, uint32, error) {
	if uint32(len(vec.raw)) < off+delta {
		return nil, off, io.ErrUnexpectedEOF
	}
	return vec.raw[off : off+delta], off + delta, nil
}
