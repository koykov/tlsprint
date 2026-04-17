package tlsprint

import "encoding/binary"

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
	pt01 = binary.LittleEndian.Uint16([]byte("01"))
	pt02 = binary.LittleEndian.Uint16([]byte("02"))
)
