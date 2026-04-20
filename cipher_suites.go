package tlsprint

import "encoding/binary"

type CipherSuite uint16

func (vec *vector) parseCipherSuites(off uint32) (_ uint32, err error) {
	var raw []byte
	if raw, off, err = vec.cut(off, 2); err != nil {
		return off, err
	}
	n := binary.LittleEndian.Uint16(raw)
	for i := uint16(0); i < n; i++ {
		if raw, off, err = vec.cut(off, 2); err != nil {
			return off, err
		}
		vec.chps = append(vec.chps, CipherSuite(binary.LittleEndian.Uint16(raw)))
	}
	return off, err
}
