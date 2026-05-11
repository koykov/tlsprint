package tlsvector

import "strconv"

func (vec *vector) JA4() string {
	// todo implement me
	return ""
}

func (vec *vector) JA4String() string {
	off := len(vec.buf)

	vec.buf = append(vec.buf, 't')

	var ver = vec.mver
	var sni byte = 'i'
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
		if ext.Type == 0x0000 && ext.Data.Len() > 0 {
			sni = 'd'
		}
	}
	vec.buf = append(vec.buf, ver.Short()...)
	vec.buf = append(vec.buf, sni)

	var chlen int
	for i := 0; i < len(vec.chps); i++ {
		cs := vec.chps[i]
		if isGREASE(cs.Raw()) {
			continue
		}
		chlen++
	}
	if chlen < 10 {
		vec.buf = append(vec.buf, '0')
	}
	vec.buf = strconv.AppendInt(vec.buf, int64(chlen), 10)

	_ = off
	return ""
}
