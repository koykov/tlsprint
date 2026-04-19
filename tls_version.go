package tlsprint

func (vec *vector) parseTLSVersion() error {
	raw := vec.raw[vec.off:]
	if len(raw) < 4 {
		return ErrTooShort
	}
	ver, err := x2u(raw[:4])
	vec.off += 4
	vec.ver = uint32(ver)
	return err
}
