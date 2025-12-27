package protocol

import (
	"fmt"

	signalerrors "github.com/deicod/signal/errors"
	"github.com/deicod/signal/keys"
	wire "github.com/deicod/signal/protocol/wire"
)

// SignalMessage represents a wire-compatible Signal ciphertext message.
type SignalMessage struct {
	inner *wire.SignalMessage
}

// NewSignalMessage constructs and serializes a SignalMessage, appending the MAC.
func NewSignalMessage(
	messageVersion uint8,
	macKey []byte,
	senderRatchet [32]byte,
	counter uint32,
	previousCounter uint32,
	ciphertext []byte,
	senderIdentity keys.IdentityKey,
	receiverIdentity keys.IdentityKey,
	pqRatchet []byte,
) (*SignalMessage, error) {
	msg, err := wire.NewSignalMessage(
		messageVersion,
		macKey,
		senderRatchet,
		counter,
		previousCounter,
		ciphertext,
		senderIdentity,
		receiverIdentity,
		pqRatchet,
	)
	if err != nil {
		return nil, err
	}
	return &SignalMessage{inner: msg}, nil
}

// ParseSignalMessage deserializes a SignalMessage from wire bytes.
func ParseSignalMessage(data []byte) (*SignalMessage, error) {
	msg, err := wire.ParseSignalMessage(data)
	if err != nil {
		return nil, err
	}
	return &SignalMessage{inner: msg}, nil
}

// Deprecated: use ParseSignalMessage instead.
func DeserializeSignalMessage(data []byte) (*SignalMessage, error) {
	return ParseSignalMessage(data)
}

// Type identifies the message type.
func (s *SignalMessage) Type() CiphertextType { return SignalType }

// Serialize returns the wire encoding (including MAC).
func (s *SignalMessage) Serialize() []byte {
	if s == nil || s.inner == nil {
		return nil
	}
	return s.inner.Serialize()
}

// MessageVersion returns the high-nibble message version.
func (s *SignalMessage) MessageVersion() uint8 {
	if s == nil || s.inner == nil {
		return 0
	}
	return s.inner.MessageVersion()
}

// SenderRatchetKey returns the sender ratchet public key (Curve25519).
func (s *SignalMessage) SenderRatchetKey() [32]byte {
	if s == nil || s.inner == nil {
		return [32]byte{}
	}
	return s.inner.SenderRatchetKey()
}

// Counter returns the message counter.
func (s *SignalMessage) Counter() uint32 {
	if s == nil || s.inner == nil {
		return 0
	}
	return s.inner.Counter()
}

// PreviousCounter returns the previous chain counter.
func (s *SignalMessage) PreviousCounter() uint32 {
	if s == nil || s.inner == nil {
		return 0
	}
	return s.inner.PreviousCounter()
}

// Ciphertext returns a copy of the message ciphertext.
func (s *SignalMessage) Ciphertext() []byte {
	if s == nil || s.inner == nil {
		return nil
	}
	return s.inner.Ciphertext()
}

// PQRatchet returns the optional PQ ratchet payload.
func (s *SignalMessage) PQRatchet() []byte {
	if s == nil || s.inner == nil {
		return nil
	}
	return s.inner.PQRatchet()
}

// VerifyMAC validates the MAC against the provided identities and mac key.
func (s *SignalMessage) VerifyMAC(senderIdentity keys.IdentityKey, receiverIdentity keys.IdentityKey, macKey []byte) (bool, error) {
	if s == nil || s.inner == nil {
		return false, fmt.Errorf("%w: signal message is nil", signalerrors.ErrInvalidMessage)
	}
	return s.inner.VerifyMAC(senderIdentity, receiverIdentity, macKey)
}
