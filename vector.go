package tlsprint

import (
	"io"

	"github.com/koykov/byteconv"
)

type Interface interface {
	Parse(p []byte) error
	ParseString(s string) error
	Reset()

	RecordType() RecordType
	RecordLegacyVersion() uint16
	RecordLength() uint16

	MessageType() MessageType
	MessageLength() uint32
	// todo describe getters
}

type vector struct {
	raw []byte
	off uint16

	rtyp   RecordType // record type (always handshake)
	protov uint16     // protocol version
	hslen  uint16     // handshake length

	mtyp MessageType // packet type
	mlen uint32      // packet length
	ver  uint32      // TLS version
	crnd []byte      // client random
	sid  []byte      // session ID
	chps []uint16    // cipher suites
	cmps []byte      // compression method
	ext  []Extension // extensions
}

func New() Interface {
	return &vector{}
}

func (vec *vector) Parse(raw []byte) (err error) {
	rl := uint16(len(raw))
	if rl == 0 {
		return ErrNoData
	}
	if raw[0] == 0x16 {
		// Record header found, so skip it.
		if rl < 5 {
			return ErrTooShort
		}
		raw = raw[5:]
		rl -= 5
	}

	vec.Reset()
	vec.raw = raw
	var off uint32

	if off, err = vec.parseRecordHeader(off); err != nil {
		return
	}
	if off, err = vec.parseHandshakeHeader(off); err != nil {
		return
	}
	if err = vec.parseTLSVersion(); err != nil {
		return
	}
	if err = vec.parseClientRandom(); err != nil {
		return err
	}
	if err = vec.parseSessionID(); err != nil {
		return
	}
	if err = vec.parseCipherSuites(); err != nil {
		return
	}
	if err = vec.parseCompressionMethod(); err != nil {
		return
	}
	if err = vec.parseExtensions(); err != nil {
		return
	}
	return
}

func (vec *vector) ParseString(raw string) error {
	return vec.Parse(byteconv.S2B(raw))
}

func (vec *vector) RecordType() RecordType {
	return vec.rtyp
}

func (vec *vector) RecordLegacyVersion() uint16 {
	return vec.protov
}

func (vec *vector) RecordLength() uint16 {
	return vec.hslen
}

func (vec *vector) MessageType() MessageType {
	return vec.mtyp
}

func (vec *vector) MessageLength() uint32 {
	return vec.mlen
}

func (vec *vector) Reset() {
	vec.raw = vec.raw[:0]

	vec.rtyp = RecordTypeUnknown
	vec.protov = 0
	vec.hslen = 0

	vec.mtyp = MessageTypeUnknown
	vec.mlen = 0
	vec.ver = 0
	vec.crnd = vec.crnd[:0]
	vec.sid = vec.sid[:0]
	vec.chps = vec.chps[:0]
	vec.cmps = vec.cmps[:0]
	vec.ext = vec.ext[:0]
}

func (vec *vector) cut(off, delta uint32) ([]byte, uint32, error) {
	if uint32(len(vec.raw)) >= off+delta {
		return nil, off, io.ErrUnexpectedEOF
	}
	return vec.raw[off : off+delta], off + delta, nil
}
