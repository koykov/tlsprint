package tlsprint

import "github.com/koykov/byteconv"

type Ctx struct {
	raw  []byte
	off  uint16
	ptyp PacketType
	plen uint32
	ver  uint32
	// ...
}

func (ctx *Ctx) Parse(raw []byte) error {
	ctx.raw = raw
	// todo implement me
	return nil
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
	// ...
}
