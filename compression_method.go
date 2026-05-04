package tlsvector

func (vec *vector) parseCompressionMethods(off uint32) (_ uint32, err error) {
	var raw []byte
	if raw, off, err = vec.cut(off, 1); err != nil {
		return off, err
	}
	if raw[0] == 0 {
		return off, err
	}
	ln := uint32(raw[0])
	if ln > 1 {
		err = ErrCompressionMethodTooLong
		return off, err
	}
	vec.cmpl = uint8(ln)
	if raw, off, err = vec.cut(off, ln); err != nil {
		return off, err
	}
	vec.cmps = raw[0]
	return off, err
}

func (vec *vector) parseCompressionMethod(off uint32) (_ uint32, err error) {
	var raw []byte
	if raw, off, err = vec.cut(off, 1); err != nil {
		return off, err
	}
	vec.cmps = raw[0]
	return off, err
}
