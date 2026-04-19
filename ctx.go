package tlsprint

import "github.com/koykov/byteconv"

type Ctx struct {
	raw  []byte
	off  uint16
	ptyp PacketType // packet type
	plen uint32     // packet length
	ver  uint32     // TLS version
	crnd []byte     // client random
	sid  []byte     // session ID
	chps []uint16   // cipher suites
	cmps []byte     // compression method
	// ...
}

func (ctx *Ctx) Parse(raw []byte) (err error) {
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

	ctx.Reset()
	ctx.raw = raw

	if err = ctx.parsePacketType(); err != nil {
		return
	}
	if err = ctx.parsePacketLength(); err != nil {
		return
	}
	if err = ctx.parseTLSVersion(); err != nil {
		return
	}
	if err = ctx.parseClientRandom(); err != nil {
		return err
	}
	if err = ctx.parseSessionID(); err != nil {
		return
	}
	if err = ctx.parseCompressionMethod(); err != nil {
		return
	}

	return
}

func (ctx *Ctx) ParseString(raw string) error {
	return ctx.Parse(byteconv.S2B(raw))
}

func (ctx *Ctx) PacketType() PacketType {
	return ctx.ptyp
}

func (ctx *Ctx) Reset() {
	ctx.raw = ctx.raw[:0]
	ctx.ptyp = PacketTypeUnknown
	ctx.plen = 0
	ctx.ver = 0
	ctx.crnd = ctx.crnd[:0]
	ctx.sid = ctx.sid[:0]
	ctx.chps = ctx.chps[:0]
	ctx.cmps = ctx.cmps[:0]
	// ...
}
