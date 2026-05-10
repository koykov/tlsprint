package tlsvector

func (vec *vector) JA4() string {
	// todo implement me
	return ""
}

func (vec *vector) JA4String() string {
	off := len(vec.buf)

	vec.buf = append(vec.buf, 't')

	var ver = vec.mver
	for i := 0; i < len(vec.ext); i++ {
		ext := &vec.ext[i]
		if ext.Type == 0x002b && ext.Data.Len() > 1 {
			data := ext.Data.Bytes()[1:]
			for j := 0; j < len(data); j += 2 {
				if data[j] == 0x03 {
					ver = MessageVersion(uint16(data[j])<<8 | uint16(data[j+1]))
					break
				}
			}
			break
		}
	}
	vec.buf = append(vec.buf, ver.Short()...)

	_ = off
	return ""
}
