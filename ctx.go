package tlsprint

type Ctx struct {
	raw  []byte
	ptyp PacketType
	plen uint16
	// ...
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
