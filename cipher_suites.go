package tlsprint

func (ctx *Ctx) parseCipherSuites() error {
	raw := ctx.raw[ctx.off:]
	if len(raw) < 4 {
		return ErrTooShort
	}
	ln, err := x2u(raw[:4])
	ctx.off += 4
	raw = ctx.raw[ctx.off:]
	if err != nil {
		return err
	}
	raw = raw[:ln*2]
	for off := 0; off+4 < len(raw); {
		cs, err := x2u(raw[off : off+4])
		if err != nil {
			return err
		}
		ctx.chps = append(ctx.chps, uint16(cs))
		off += 4
	}
	return nil
}
