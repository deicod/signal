package protocol

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// SignalMessage represents a standard Signal ciphertext message.
type SignalMessage struct {
	Version         uint8
	RatchetKey      [32]byte
	Counter         uint32
	PreviousCounter uint32
	Ciphertext      []byte
	MAC             []byte
}

// Type identifies the message type.
func (s *SignalMessage) Type() CiphertextType { return SignalType }

// Serialize encodes the message into a byte slice.
func (s *SignalMessage) Serialize() []byte {
	ctLen := len(s.Ciphertext)
	macLen := len(s.MAC)
	out := make([]byte, 1+32+4+4+4+ctLen+2+macLen)
	pos := 0
	out[pos] = s.Version
	pos++
	copy(out[pos:pos+32], s.RatchetKey[:])
	pos += 32
	binary.BigEndian.PutUint32(out[pos:pos+4], s.Counter)
	pos += 4
	binary.BigEndian.PutUint32(out[pos:pos+4], s.PreviousCounter)
	pos += 4
	binary.BigEndian.PutUint32(out[pos:pos+4], uint32(ctLen))
	pos += 4
	copy(out[pos:pos+ctLen], s.Ciphertext)
	pos += ctLen
	binary.BigEndian.PutUint16(out[pos:pos+2], uint16(macLen))
	pos += 2
	copy(out[pos:], s.MAC)
	return out
}

// DeserializeSignalMessage decodes a SignalMessage from bytes.
func DeserializeSignalMessage(data []byte) (*SignalMessage, error) {
	if len(data) < 1+32+4+4+4+2 {
		return nil, fmt.Errorf("signal message: too short")
	}
	pos := 0
	msg := &SignalMessage{Version: data[pos]}
	pos++
	copy(msg.RatchetKey[:], data[pos:pos+32])
	pos += 32
	msg.Counter = binary.BigEndian.Uint32(data[pos : pos+4])
	pos += 4
	msg.PreviousCounter = binary.BigEndian.Uint32(data[pos : pos+4])
	pos += 4
	ctLen := int(binary.BigEndian.Uint32(data[pos : pos+4]))
	pos += 4
	if pos+ctLen+2 > len(data) {
		return nil, fmt.Errorf("signal message: truncated ciphertext")
	}
	msg.Ciphertext = append([]byte(nil), data[pos:pos+ctLen]...)
	pos += ctLen
	macLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	if pos+macLen > len(data) {
		return nil, fmt.Errorf("signal message: truncated mac")
	}
	msg.MAC = append([]byte(nil), data[pos:pos+macLen]...)
	return msg, nil
}

// ComputeMAC calculates an HMAC-SHA256 over the message fields (excluding MAC) and stores it.
func (s *SignalMessage) ComputeMAC(macKey []byte) []byte {
	mac := hmac.New(sha256.New, macKey)
	mac.Write(s.payloadForMAC())
	s.MAC = mac.Sum(nil)
	return s.MAC
}

// VerifyMAC checks the stored MAC against a freshly computed MAC.
func (s *SignalMessage) VerifyMAC(macKey []byte) bool {
	if len(s.MAC) == 0 {
		return false
	}
	expected := hmac.New(sha256.New, macKey)
	expected.Write(s.payloadForMAC())
	sum := expected.Sum(nil)
	return hmac.Equal(sum, s.MAC)
}

func (s *SignalMessage) payloadForMAC() []byte {
	ctLen := len(s.Ciphertext)
	out := make([]byte, 1+32+4+4+4+ctLen)
	pos := 0
	out[pos] = s.Version
	pos++
	copy(out[pos:pos+32], s.RatchetKey[:])
	pos += 32
	binary.BigEndian.PutUint32(out[pos:pos+4], s.Counter)
	pos += 4
	binary.BigEndian.PutUint32(out[pos:pos+4], s.PreviousCounter)
	pos += 4
	binary.BigEndian.PutUint32(out[pos:pos+4], uint32(ctLen))
	pos += 4
	copy(out[pos:], s.Ciphertext)
	return out
}
