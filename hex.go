package tlsvector

import "math"

func x2u(p []byte) (r uint64, err error) {
	n := len(p)
	if n == 0 {
		err = ErrNoData
		return
	}
	if n > 16 {
		err = ErrHexTooLong
		return
	}
	_, _ = p[n-1], dig16[math.MaxUint8-1]
	for i := 0; i < n; i++ {
		d := dig16[p[i]]
		if d > 15 {
			return 0, ErrHexBadByte
		}
		r = r<<4 | d
	}
	return
}

func x2u16(p []byte) (uint16, error) {
	v, err := x2u(p)
	return uint16(v), err
}

var dig16 [math.MaxUint8]uint64

func init() {
	for i := uint8(0); i < math.MaxUint8; i++ {
		dig16[i] = math.MaxUint8
	}
	dig16['0'] = 0
	dig16['1'] = 1
	dig16['2'] = 2
	dig16['3'] = 3
	dig16['4'] = 4
	dig16['5'] = 5
	dig16['6'] = 6
	dig16['7'] = 7
	dig16['8'] = 8
	dig16['9'] = 9
	dig16['A'] = 10
	dig16['B'] = 11
	dig16['C'] = 12
	dig16['D'] = 13
	dig16['E'] = 14
	dig16['F'] = 15
	dig16['a'] = 10
	dig16['b'] = 11
	dig16['c'] = 12
	dig16['d'] = 13
	dig16['e'] = 14
	dig16['f'] = 15
}
