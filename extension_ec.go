package tlsvector

import "github.com/koykov/byteconv"

type EllipticCurve uint16

func (ec EllipticCurve) Raw() uint16 {
	return uint16(ec)
}

func (ec EllipticCurve) String() string {
	enc := __ec[ec]
	lo, hi := uint16(enc>>16), uint16(enc)
	return byteconv.B2S(__ec_buf[lo:hi])
}
