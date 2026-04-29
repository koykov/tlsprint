package tlsvector

import "github.com/koykov/byteconv"

type ECPointFormats uint8

func (ecpf ECPointFormats) Raw() uint8 {
	return uint8(ecpf)
}

func (ecpf ECPointFormats) String() string {
	enc := __ecpf[ecpf]
	lo, hi := uint16(enc>>16), uint16(enc)
	return byteconv.B2S(__ecpf_buf[lo:hi])
}
