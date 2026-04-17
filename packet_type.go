package tlsprint

import (
	"encoding/binary"
	"math"
)

type PacketType uint8

const (
	PacketTypeUnknown = iota
	PacketTypeClientHello
	PacketTypeServerHello
)

func (pt PacketType) String() string {
	if pt > PacketTypeServerHello {
		return ptyps[PacketTypeUnknown]
	}
	return ptyps[pt]
}

func (ctx *Ctx) parsePacketType() error {
	raw := ctx.raw[ctx.off:]
	if len(raw) < 2 {
		return ErrTooShort
	}
	pt := binary.LittleEndian.Uint16(raw[ctx.off : ctx.off+2])
	ctx.off += 2
	switch pt {
	case pt01:
		ctx.ptyp = PacketTypeClientHello
	case pt02:
		ctx.ptyp = PacketTypeServerHello
	default:
		return ErrUnknownPacketType
	}
	return nil
}

var (
	ptyps [math.MaxUint8]string
	pt01  = binary.LittleEndian.Uint16([]byte("01"))
	pt02  = binary.LittleEndian.Uint16([]byte("02"))
)

func init() {
	ptyps[PacketTypeUnknown] = "UNKNOWN"
	ptyps[PacketTypeClientHello] = "CLIENT_HELLO"
	ptyps[PacketTypeServerHello] = "SERVER_HELLO"
}
