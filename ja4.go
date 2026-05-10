package tlsvector

func (vec *vector) JA4() string {
	// todo implement me
	return ""
}

func (vec *vector) JA4String() string {
	off := len(vec.buf)

	vec.buf = append(vec.buf, 't')
	vec.buf = append(vec.buf, vec.mver.Short()...)

	_ = off
	return ""
}
