package tlsvector

import "strconv"

func appendHexU16(dst []byte, u16 uint16) []byte {
	off := len(dst)
	dst = append(dst, "0000"...)
	dst = strconv.AppendUint(dst, uint64(u16), 16)
	copy(dst[off:off+4], dst[len(dst)-4:])
	return dst[:off+4]
}

func appendHexB2(dst []byte, b2 [2]byte) []byte {
	off := len(dst)
	dst = append(dst, "00"...)
	dst = strconv.AppendUint(dst, uint64(b2[0]), 16)
	copy(dst[off:off+2], dst[len(dst)-2:])
	dst = dst[:off+2]

	off = len(dst)
	dst = append(dst, "00"...)
	dst = strconv.AppendUint(dst, uint64(b2[1]), 16)
	copy(dst[off:off+2], dst[len(dst)-2:])
	return dst[:off+2]
}
