package ratchet

import (
	"encoding/binary"
	"errors"
	"fmt"

	"crypto/aes"
	"crypto/cipher"
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

// EncryptHeader encrypts the serialized header using AES-GCM with provided key and nonce.
func EncryptHeader(h *Header, key, nonce []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("header: key must be 32 bytes")
	}
	if len(nonce) != 12 {
		return nil, fmt.Errorf("header: nonce must be 12 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("header: cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("header: gcm: %w", err)
	}
	return gcm.Seal(nil, nonce, h.Serialize(), nil), nil
}

// DecryptHeader decrypts an encrypted header using AES-GCM.
func DecryptHeader(key, nonce, ciphertext []byte) (*Header, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("header: key must be 32 bytes")
	}
	if len(nonce) != 12 {
		return nil, fmt.Errorf("header: nonce must be 12 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("header: cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("header: gcm: %w", err)
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("header: decrypt: %w", err)
	}
	return DeserializeHeader(plain)
}
