package tlsprint

import "github.com/koykov/byteconv"

type Ctx struct {
	raw  []byte
	off  uint16
	ptyp PacketType
	plen uint32
	ver  uint32
	crnd []byte
	// ...
}

func (ctx *Ctx) Parse(raw []byte) (err error) {
	ctx.Reset()
	ctx.raw = raw
	rl := uint16(len(raw))

	if err = ctx.parsePacketType(); err != nil {
		return
	}
	if err = ctx.parsePacketLength(); err != nil {
		return
	}
	if err = ctx.parseTLSVersion(); err != nil {
		return
	}

	if rl-ctx.off < 64 {
		err = ErrTooShort
		return
	}
	ctx.crnd = ctx.raw[ctx.off : ctx.off+64]
	ctx.off += 64

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
	// ...
}
