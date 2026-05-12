package tlsvector

import (
	"fmt"
	"slices"
	"strconv"
)

func (vec *vector) JA4() string {
	// todo implement me
	return ""
}

func (vec *vector) JA4String() string {
	off := len(vec.buf)

	// meta part

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

	var extlen int
	var alpn = [2]byte{'0', '0'}
	for i := 0; i < len(vec.ext); i++ {
		ext := vec.ext[i]
		if isGREASE(ext.Type.Raw()) {
			continue
		}
		if ext.Type == 0x0010 {
			ealpn := NewExtensionApplicationLayerProtocolNegotiation(ext.Data.Bytes())
			var ok bool
			ealpn.Each(func(protocol []byte) {
				if len(protocol) >= 2 && !ok {
					ok = true
					alpn[0], alpn[1] = protocol[0], protocol[len(protocol)-1]
				}
			})
		}
		extlen++
	}
	if extlen < 10 {
		vec.buf = append(vec.buf, '0')
	}
	vec.buf = strconv.AppendInt(vec.buf, int64(extlen), 10)
	vec.buf = append(vec.buf, alpn[:]...)

	// cipher suites part
	vec.buf16 = vec.buf16[:0]
	for i := 0; i < len(vec.chps); i++ {
		cs := vec.chps[i].Raw()
		if isGREASE(cs) || cs == 0x0000 || cs == 0x0010 {
			continue
		}
		vec.buf16 = append(vec.buf16, cs)
	}
	slices.Sort(vec.buf16)
	vec.buf = append(vec.buf, '_')
	for i := 0; i < len(vec.buf16); i++ {
		if i > 0 {
			vec.buf = append(vec.buf, ',')
		}
		vec.buf = fmt.Appendf(vec.buf, "%04x", vec.buf16[i])
	}

	// extensions part
	vec.buf16 = vec.buf16[:0]
	for i := 0; i < len(vec.ext); i++ {
		et := vec.ext[i].Type.Raw()
		if isGREASE(et) {
			continue
		}
		vec.buf16 = append(vec.buf16, et)
	}
	slices.Sort(vec.buf16)
	vec.buf = append(vec.buf, '_')
	for i := 0; i < len(vec.buf16); i++ {
		if i > 0 {
			vec.buf = append(vec.buf, ',')
		}
		vec.buf = fmt.Appendf(vec.buf, "%04x", vec.buf16[i])
	}

	_ = off
	return ""
}
