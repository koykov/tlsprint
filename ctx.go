package tlsprint

type PacketType uint8

const (
	PacketTypeUnknown = iota
	PacketTypeClientHello
	PacketTypeServerHello
)

type Ctx struct {
	raw  []byte
	ptyp PacketType
	plen uint16
	// ...
}

func (ctx *Ctx) Reset() {
	ctx.raw = ctx.raw[:0]
	ctx.ptyp = PacketTypeUnknown
	ctx.plen = 0
	// ...
}
