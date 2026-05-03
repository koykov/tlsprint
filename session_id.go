package tlsvector

func (vec *vector) parseSessionID(off uint32) (_ uint32, err error) {
	var raw []byte
	if raw, off, err = vec.cut(off, 1); err != nil {
		return off, err
	}
	if raw[0] == 0 {
		return off, err
	}

	lo, hi := off, off+uint32(raw[0])
	vec.sid = uint64(lo)<<32 | uint64(hi)
	return hi, err
}
