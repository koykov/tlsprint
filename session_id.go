package tlsprint

func (vec *vector) parseSessionID(off uint32) (_ uint32, err error) {
	var raw []byte
	if raw, off, err = vec.cut(off, 1); err != nil {
		return off, err
	}
	if raw[0] == 0 {
		return off, err
	}

	if raw, off, err = vec.cut(off, uint32(raw[0])); err != nil {
		return off, err
	}
	vec.sid = raw
	return off, err
}
