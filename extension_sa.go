package tlsvector

import "github.com/koykov/byteconv"

type SignatureAlgorithm uint8

func (sa SignatureAlgorithm) Raw() uint8 {
	return uint8(sa)
}

func (sa SignatureAlgorithm) String() string {
	enc := __sa[sa]
	lo, hi := uint16(enc>>16), uint16(enc)
	return byteconv.B2S(__sa_buf[lo:hi])
}
