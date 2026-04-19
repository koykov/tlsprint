package tlsprint

func (vec *vector) parseCipherSuites() error {
	raw := vec.raw[vec.off:]
	if len(raw) < 4 {
		return ErrTooShort
	}
	ln, err := x2u(raw[:4])
	vec.off += 4
	raw = vec.raw[vec.off:]
	if err != nil {
		return err
	}
	raw = raw[:ln*2]
	for off := 0; off+4 < len(raw); {
		cs, err := x2u(raw[off : off+4])
		if err != nil {
			return err
		}
		vec.chps = append(vec.chps, uint16(cs))
		off += 4
	}
	return nil
}
