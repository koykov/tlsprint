package tlsprint

import "math"

type PacketType uint8

const (
	PacketTypeUnknown = iota
	PacketTypeClientHello
	PacketTypeServerHello
)

func (pt PacketType) String() string {
	return ptyps[pt]
}

var ptyps [math.MaxUint8]string

func init() {
	ptyps[PacketTypeUnknown] = "UNKNOWN"
	ptyps[PacketTypeClientHello] = "CLIENT_HELLO"
	ptyps[PacketTypeServerHello] = "SERVER_HELLO"
}
