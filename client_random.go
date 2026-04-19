package tlsprint

func (vec *vector) parseClientRandom() error {
	raw := vec.raw[vec.off:]
	if len(raw) < 64 {
		return ErrTooShort
	}
	vec.crnd = raw[:64]
	vec.off += 64
	return nil
}
