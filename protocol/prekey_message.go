package protocol

import (
	"fmt"

	signalerrors "github.com/deicod/signal/errors"
	"github.com/deicod/signal/keys"
	wire "github.com/deicod/signal/protocol/wire"
)

// PreKeyMessage wraps the initial Signal message along with identity and pre-key metadata.
type PreKeyMessage struct {
	inner *wire.PreKeySignalMessage
}

// NewPreKeyMessage constructs and serializes a PreKeyMessage.
func NewPreKeyMessage(
	messageVersion uint8,
	registrationID uint32,
	preKeyID *uint32,
	signedPreKeyID uint32,
	kyberPreKeyID *uint32,
	kyberCiphertext []byte,
	baseKey [32]byte,
	identityKey keys.IdentityKey,
	message *SignalMessage,
) (*PreKeyMessage, error) {
	if message == nil || message.inner == nil {
		return nil, fmt.Errorf("%w: missing inner signal message", signalerrors.ErrInvalidMessage)
	}
	msg, err := wire.NewPreKeySignalMessage(
		messageVersion,
		registrationID,
		preKeyID,
		signedPreKeyID,
		kyberPreKeyID,
		kyberCiphertext,
		baseKey,
		identityKey,
		message.inner,
	)
	if err != nil {
		return nil, err
	}
	return &PreKeyMessage{inner: msg}, nil
}

// ParsePreKeyMessage deserializes a PreKeyMessage from wire bytes.
func ParsePreKeyMessage(data []byte) (*PreKeyMessage, error) {
	msg, err := wire.ParsePreKeySignalMessage(data)
	if err != nil {
		return nil, err
	}
	return &PreKeyMessage{inner: msg}, nil
}

// DeserializePreKeyMessage deserializes a PreKeyMessage from wire bytes.
// Deprecated: use ParsePreKeyMessage instead.
func DeserializePreKeyMessage(data []byte) (*PreKeyMessage, error) {
	return ParsePreKeyMessage(data)
}

// Type identifies the message type.
func (p *PreKeyMessage) Type() CiphertextType { return PreKeyType }

// Serialize returns the wire encoding.
func (p *PreKeyMessage) Serialize() []byte {
	if p == nil || p.inner == nil {
		return nil
	}
	return p.inner.Serialize()
}

// MessageVersion returns the high-nibble message version.
func (p *PreKeyMessage) MessageVersion() uint8 {
	if p == nil || p.inner == nil {
		return 0
	}
	return p.inner.MessageVersion()
}

// RegistrationID returns the sender registration ID.
func (p *PreKeyMessage) RegistrationID() uint32 {
	if p == nil || p.inner == nil {
		return 0
	}
	return p.inner.RegistrationID()
}

// PreKeyID returns the optional pre-key ID.
func (p *PreKeyMessage) PreKeyID() *uint32 {
	if p == nil || p.inner == nil {
		return nil
	}
	return p.inner.PreKeyID()
}

// SignedPreKeyID returns the signed pre-key ID.
func (p *PreKeyMessage) SignedPreKeyID() uint32 {
	if p == nil || p.inner == nil {
		return 0
	}
	return p.inner.SignedPreKeyID()
}

// KyberPreKeyID returns the optional Kyber pre-key ID.
func (p *PreKeyMessage) KyberPreKeyID() *uint32 {
	if p == nil || p.inner == nil {
		return nil
	}
	return p.inner.KyberPreKeyID()
}

// KyberCiphertext returns the Kyber ciphertext payload.
func (p *PreKeyMessage) KyberCiphertext() []byte {
	if p == nil || p.inner == nil {
		return nil
	}
	return p.inner.KyberCiphertext()
}

// BaseKey returns the initiator base key.
func (p *PreKeyMessage) BaseKey() [32]byte {
	if p == nil || p.inner == nil {
		return [32]byte{}
	}
	return p.inner.BaseKey()
}

// IdentityKey returns the initiator identity key.
func (p *PreKeyMessage) IdentityKey() keys.IdentityKey {
	if p == nil || p.inner == nil {
		return keys.IdentityKey{}
	}
	return p.inner.IdentityKey()
}

// SignalMessage returns the embedded SignalMessage.
func (p *PreKeyMessage) SignalMessage() *SignalMessage {
	if p == nil || p.inner == nil {
		return nil
	}
	message := p.inner.Message()
	if message == nil {
		return nil
	}
	return &SignalMessage{inner: message}
}

// VerifyMAC delegates to the nested signal message MAC verification.
func (p *PreKeyMessage) VerifyMAC(senderIdentity keys.IdentityKey, receiverIdentity keys.IdentityKey, macKey []byte) (bool, error) {
	msg := p.SignalMessage()
	if msg == nil {
		return false, fmt.Errorf("%w: missing signal message", signalerrors.ErrInvalidMessage)
	}
	return msg.VerifyMAC(senderIdentity, receiverIdentity, macKey)
}
