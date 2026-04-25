package tlsvector

import "encoding/binary"

type ExtensionType uint16

func (et ExtensionType) Raw() uint16 {
	return uint16(et)
}

func (et ExtensionType) String() string {
	return ""
}

type Extension struct {
	Type ExtensionType
	Data []byte
}

func (vec *vector) parseExtensions(off uint32) (_ uint32, err error) {
	var raw []byte
	if raw, off, err = vec.cut(off, 2); err != nil {
		return off, err
	}
	ln := binary.BigEndian.Uint16(raw)
	for i := uint16(0); i < ln; {
		if raw, off, err = vec.cut(off, 4); err != nil {
			return off, err
		}
		i += 4
		var e Extension
		e.Type = ExtensionType(binary.BigEndian.Uint16(raw[0:2]))
		eln := binary.BigEndian.Uint16(raw[2:4])
		if raw, off, err = vec.cut(off, uint32(eln)); err != nil {
			return off, err
		}
		e.Data = raw
		vec.ext = append(vec.ext, e)
		i += eln
	}

	return off, nil
}
