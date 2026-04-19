package tlsprint

import "github.com/koykov/byteconv"

type Interface interface {
	Parse(p []byte) error
	ParseString(s string) error
	Reset()
	PacketType() PacketType
	// todo describe getters
}

type vector struct {
	raw  []byte
	off  uint16
	ptyp PacketType  // packet type
	plen uint32      // packet length
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

	if err = vec.parsePacketType(); err != nil {
		return
	}
	if err = vec.parsePacketLength(); err != nil {
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

func (vec *vector) PacketType() PacketType {
	return vec.ptyp
}

func (vec *vector) Reset() {
	vec.raw = vec.raw[:0]
	vec.ptyp = PacketTypeUnknown
	vec.plen = 0
	vec.ver = 0
	vec.crnd = vec.crnd[:0]
	vec.sid = vec.sid[:0]
	vec.chps = vec.chps[:0]
	vec.cmps = vec.cmps[:0]
	vec.ext = vec.ext[:0]
}
