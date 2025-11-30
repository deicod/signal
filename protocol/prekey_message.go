package protocol

import (
	"encoding/binary"
	"fmt"

	"github.com/deicod/signal/keys"
)

// PreKeyMessage wraps the initial Signal message along with identity and pre-key metadata.
type PreKeyMessage struct {
	Version        uint8
	RegistrationID uint32
	PreKeyID       *uint32
	SignedPreKeyID uint32
	BaseKey        [32]byte
	IdentityKey    keys.IdentityKey
	SignalMessage  *SignalMessage
}

// Type identifies the message type.
func (p *PreKeyMessage) Type() CiphertextType { return PreKeyType }

// Serialize encodes the PreKeyMessage into bytes.
func (p *PreKeyMessage) Serialize() []byte {
	hasPreKey := byte(0)
	if p.PreKeyID != nil {
		hasPreKey = 1
	}
	identityBytes, _ := p.IdentityKey.Serialize()
	signalBytes := p.SignalMessage.Serialize()

	out := make([]byte, 1+4+1+4+4+32+2+len(identityBytes)+4+len(signalBytes))
	pos := 0
	out[pos] = p.Version
	pos++
	binary.BigEndian.PutUint32(out[pos:pos+4], p.RegistrationID)
	pos += 4
	out[pos] = hasPreKey
	pos++
	if hasPreKey == 1 {
		binary.BigEndian.PutUint32(out[pos:pos+4], *p.PreKeyID)
		pos += 4
	} else {
		pos += 4
	}
	binary.BigEndian.PutUint32(out[pos:pos+4], p.SignedPreKeyID)
	pos += 4
	copy(out[pos:pos+32], p.BaseKey[:])
	pos += 32
	binary.BigEndian.PutUint16(out[pos:pos+2], uint16(len(identityBytes)))
	pos += 2
	copy(out[pos:pos+len(identityBytes)], identityBytes)
	pos += len(identityBytes)
	binary.BigEndian.PutUint32(out[pos:pos+4], uint32(len(signalBytes)))
	pos += 4
	copy(out[pos:], signalBytes)
	return out
}

// DeserializePreKeyMessage decodes a PreKeyMessage from bytes.
func DeserializePreKeyMessage(data []byte) (*PreKeyMessage, error) {
	if len(data) < 1+4+1+4+4+32+2+4 {
		return nil, fmt.Errorf("pre-key message: too short")
	}
	pos := 0
	msg := &PreKeyMessage{}
	msg.Version = data[pos]
	pos++
	msg.RegistrationID = binary.BigEndian.Uint32(data[pos : pos+4])
	pos += 4
	hasPreKey := data[pos]
	pos++
	if hasPreKey == 1 {
		id := binary.BigEndian.Uint32(data[pos : pos+4])
		msg.PreKeyID = &id
	}
	pos += 4
	msg.SignedPreKeyID = binary.BigEndian.Uint32(data[pos : pos+4])
	pos += 4
	copy(msg.BaseKey[:], data[pos:pos+32])
	pos += 32

	if pos+2 > len(data) {
		return nil, fmt.Errorf("pre-key message: truncated identity length")
	}
	identityLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	if pos+identityLen+4 > len(data) {
		return nil, fmt.Errorf("pre-key message: truncated identity")
	}
	identity, err := keys.DeserializeIdentityKey(data[pos : pos+identityLen])
	if err != nil {
		return nil, fmt.Errorf("pre-key message: %w", err)
	}
	msg.IdentityKey = *identity
	pos += identityLen

	if pos+4 > len(data) {
		return nil, fmt.Errorf("pre-key message: truncated signal length")
	}
	signalLen := int(binary.BigEndian.Uint32(data[pos : pos+4]))
	pos += 4
	if pos+signalLen > len(data) {
		return nil, fmt.Errorf("pre-key message: truncated signal message")
	}
	signalMsg, err := DeserializeSignalMessage(data[pos : pos+signalLen])
	if err != nil {
		return nil, fmt.Errorf("pre-key message: %w", err)
	}
	msg.SignalMessage = signalMsg
	return msg, nil
}

// VerifyMAC delegates to the nested signal message MAC verification.
func (p *PreKeyMessage) VerifyMAC(macKey []byte) bool {
	if p == nil || p.SignalMessage == nil {
		return false
	}
	return p.SignalMessage.VerifyMAC(macKey)
}
