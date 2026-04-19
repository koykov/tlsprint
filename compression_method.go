package tlsprint

func (vec *vector) parseCompressionMethod() error {
	raw := vec.raw[vec.off:]
	if len(raw) < 2 {
		return ErrTooShort
	}
	ln, err := x2u(raw[:2])
	vec.off += 2
	raw = vec.raw[vec.off:]
	if err != nil {
		return err
	}
	if uint64(len(raw)) < ln*2 {
		return ErrTooShort
	}
	vec.cmps = raw[:ln*2]
	return nil
}
