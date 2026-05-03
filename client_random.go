package tlsvector

func (vec *vector) parseClientRandom(off uint32) (_ uint32, err error) {
	vec.rand = uint64(off)<<32 | uint64(off+32)
	return off + 32, err
}
