package tlsprint

func (ctx *Ctx) parseTLSVersion() error {
	raw := ctx.raw[ctx.off:]
	if len(raw) < 4 {
		return ErrTooShort
	}
	ver, err := x2u(raw[:4])
	ctx.off += 4
	ctx.ver = uint32(ver)
	return err
}
