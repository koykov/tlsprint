package tlsprint

func (ctx *Ctx) parsePacketLength() error {
	raw := ctx.raw[ctx.off:]
	if len(raw) < 6 {
		return ErrTooShort
	}
	pl, err := x2u(raw[:6])
	ctx.off += 6
	ctx.plen = uint32(pl)
	return err
}
