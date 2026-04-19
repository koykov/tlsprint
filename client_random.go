package tlsprint

func (ctx *Ctx) parseClientRandom() error {
	raw := ctx.raw[ctx.off:]
	if len(raw) < 64 {
		return ErrTooShort
	}
	ctx.crnd = raw[:64]
	ctx.off += 64
	return nil
}
