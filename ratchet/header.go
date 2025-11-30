package ratchet

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Header carries ratchet header info.
type Header struct {
	DH [32]byte
	PN uint32
	N  uint32
}

// Serialize encodes header into bytes.
func (h *Header) Serialize() []byte {
	out := make([]byte, 32+4+4)
	copy(out[:32], h.DH[:])
	binary.BigEndian.PutUint32(out[32:36], h.PN)
	binary.BigEndian.PutUint32(out[36:40], h.N)
	return out
}

// DeserializeHeader decodes bytes into a Header.
func DeserializeHeader(data []byte) (*Header, error) {
	if len(data) != 40 {
		return nil, fmt.Errorf("header: invalid length %d", len(data))
	}
	var h Header
	copy(h.DH[:], data[:32])
	h.PN = binary.BigEndian.Uint32(data[32:36])
	h.N = binary.BigEndian.Uint32(data[36:40])
	return &h, nil
}

// Validate basic header fields.
func (h *Header) Validate() error {
	if h == nil {
		return errors.New("header is nil")
	}
	return nil
}
