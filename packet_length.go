package tlsprint

func (vec *vector) parsePacketLength() error {
	raw := vec.raw[vec.off:]
	if len(raw) < 6 {
		return ErrTooShort
	}
	pl, err := x2u(raw[:6])
	vec.off += 6
	vec.plen = uint32(pl)
	return err
}
