package tlsvector

import "encoding/binary"

type ExtensionType uint16

type Extension struct {
	Type ExtensionType
	Data []byte
}

func (vec *vector) parseExtensions() error {
	raw := vec.raw[vec.off:]
	if len(raw) < 4 {
		return ErrTooShort
	}
	ln, err := x2u(raw[:4])
	if err != nil {
		return err
	}
	vec.off += 4
	raw = vec.raw[vec.off:]
	var off uint64
	for off < ln*2 {
		var ext Extension
		if len(raw) < 2 {
			return ErrTooShort
		}
		ext.Type = ExtensionType(binary.LittleEndian.Uint16(raw[:2]))
		vec.off += 2
		raw = vec.raw[vec.off:]

		if len(raw) < 2 {
			return ErrTooShort
		}
		eln, err := x2u(raw[:2])
		vec.off += 2
		raw = vec.raw[vec.off:]
		if err != nil {
			return err
		}
		if uint64(len(raw)) < eln*2 {
			return ErrTooShort
		}
		ext.Data = raw[:eln*2]
		vec.off += uint16(eln * 2)
		raw = vec.raw[vec.off:]

	}
	return nil
}
