package tlsvector

func (vec *vector) parseClientRandom(off uint32) (_ uint32, err error) {
	var raw []byte
	if raw, off, err = vec.cut(off, 32); err != nil {
		return off, err
	}
	vec.rand = raw
	return off, err
}
