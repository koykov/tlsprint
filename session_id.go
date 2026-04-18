package tlsprint

func (ctx *Ctx) parseSessionID() error {
	raw := ctx.raw[ctx.off:]
	if len(raw) < 2 {
		return ErrTooShort
	}
	ln, err := x2u(raw[:2])
	ctx.off += 2
	raw = ctx.raw[ctx.off:]
	if err != nil {
		return err
	}
	if uint64(len(raw)) < ln*2 {
		return ErrTooShort
	}
	ctx.sid = raw[:ln*2]
	return nil
}
