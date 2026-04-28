package tlsvector

import "github.com/koykov/byteconv"

type ClientCertificateType uint8

func (cct ClientCertificateType) Raw() uint8 {
	return uint8(cct)
}

func (cct ClientCertificateType) String() string {
	enc := __cct[cct]
	lo, hi := uint16(enc>>16), uint16(enc)
	return byteconv.B2S(__cct_buf[lo:hi])
}
