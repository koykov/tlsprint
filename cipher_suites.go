package tlsvector

import (
	"encoding/binary"

	"github.com/koykov/byteconv"
)

type CipherSuite uint16

func (cs CipherSuite) Raw() uint16 {
	return uint16(cs)
}

func (cs CipherSuite) String() (s string) {
	enc := __cs[cs]
	lo, hi := uint16(enc>>16), uint16(enc)
	if s = byteconv.B2S(__cs_buf[lo:hi]); len(s) == 0 {
		s = "Reserved"
	}
	return
}

func (vec *vector) parseCipherSuites(off uint32) (_ uint32, err error) {
	var raw []byte
	if raw, off, err = vec.cut(off, 2); err != nil {
		return off, err
	}
	n := binary.BigEndian.Uint16(raw)
	for i := uint16(0); i < n; i += 2 {
		if raw, off, err = vec.cut(off, 2); err != nil {
			return off, err
		}
		vec.chps = append(vec.chps, CipherSuite(binary.BigEndian.Uint16(raw)))
	}
	return off, err
}
