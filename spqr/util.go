package spqr

import "encoding/binary"

func epochBytes(epoch uint64) []byte {
	var out [8]byte
	binary.BigEndian.PutUint64(out[:], epoch)
	return out[:]
}

func appendUint64(out []byte, v uint64) []byte {
	return append(out,
		byte(v>>56),
		byte(v>>48),
		byte(v>>40),
		byte(v>>32),
		byte(v>>24),
		byte(v>>16),
		byte(v>>8),
		byte(v),
	)
}

func readUint64(b []byte) uint64 {
	return uint64(b[0])<<56 |
		uint64(b[1])<<48 |
		uint64(b[2])<<40 |
		uint64(b[3])<<32 |
		uint64(b[4])<<24 |
		uint64(b[5])<<16 |
		uint64(b[6])<<8 |
		uint64(b[7])
}

func appendUint32(out []byte, v uint32) []byte {
	return append(out, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func readUint32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func appendUint16(out []byte, v uint16) []byte {
	return append(out, byte(v>>8), byte(v))
}

func readUint16(b []byte) uint16 {
	return uint16(b[0])<<8 | uint16(b[1])
}

func appendBytes(out []byte, b []byte) []byte {
	out = appendUint32(out, uint32(len(b)))
	return append(out, b...)
}

func readBytes(data []byte, pos *int) ([]byte, error) {
	if *pos+4 > len(data) {
		return nil, ErrStateDecode
	}
	n := int(readUint32(data[*pos : *pos+4]))
	*pos += 4
	if n < 0 || *pos+n > len(data) {
		return nil, ErrStateDecode
	}
	out := append([]byte(nil), data[*pos:*pos+n]...)
	*pos += n
	return out, nil
}
