package session

import (
	"fmt"

	"github.com/deicod/signal/ratchet"
	"github.com/deicod/signal/store"
)

// CiphertextType identifies the kind of message.
type CiphertextType int

const (
	// SignalType is a standard Double Ratchet message.
	SignalType CiphertextType = iota
)

// CiphertextMessage abstracts ciphertext envelopes.
type CiphertextMessage interface {
	Type() CiphertextType
}

// SignalCiphertext wraps a ratchet message.
type SignalCiphertext struct {
	Message *ratchet.Message
}

// Type implements CiphertextMessage.
func (s *SignalCiphertext) Type() CiphertextType { return SignalType }

// SessionCipher offers high-level encryption/decryption for a remote address.
type SessionCipher struct {
	store         store.ProtocolStore
	remoteAddress store.Address
	builder       *SessionBuilder
}

// NewSessionCipher builds a cipher bound to a ProtocolStore and remote address.
func NewSessionCipher(s store.ProtocolStore, addr store.Address) *SessionCipher {
	return &SessionCipher{
		store:         s,
		remoteAddress: addr,
		builder:       NewSessionBuilder(s, addr),
	}
}

// Encrypt uses the current session to encrypt plaintext. A session must exist in the store.
func (c *SessionCipher) Encrypt(plaintext []byte) (*SignalCiphertext, error) {
	session, err := c.loadSession()
	if err != nil {
		return nil, err
	}

	msg, err := session.CurrentState().Encrypt(plaintext, session.AssociatedData())
	if err != nil {
		return nil, fmt.Errorf("session encrypt: %w", err)
	}

	if err := c.saveSession(session); err != nil {
		return nil, err
	}
	return &SignalCiphertext{Message: msg}, nil
}

// Decrypt decrypts a ciphertext message using the current session.
func (c *SessionCipher) Decrypt(message CiphertextMessage) ([]byte, error) {
	session, err := c.loadSession()
	if err != nil {
		return nil, err
	}

	signalMsg, ok := message.(*SignalCiphertext)
	if !ok || signalMsg.Message == nil {
		return nil, fmt.Errorf("session decrypt: unsupported message type")
	}

	plaintext, err := session.CurrentState().Decrypt(signalMsg.Message, session.AssociatedData())
	if err != nil {
		return nil, fmt.Errorf("session decrypt: %w", err)
	}

	if err := c.saveSession(session); err != nil {
		return nil, err
	}
	return plaintext, nil
}

func (c *SessionCipher) loadSession() (*Session, error) {
	record, err := c.store.LoadSession(c.remoteAddress)
	if err != nil {
		return nil, fmt.Errorf("load session: %w", err)
	}
	if record == nil || record.Data == nil {
		return nil, fmt.Errorf("no session for %v", c.remoteAddress)
	}
	session, ok := record.Data.(*Session)
	if !ok || session == nil {
		return nil, fmt.Errorf("invalid session record for %v", c.remoteAddress)
	}
	return session, nil
}

func (c *SessionCipher) saveSession(session *Session) error {
	if session == nil {
		return fmt.Errorf("session is nil")
	}
	return c.store.StoreSession(c.remoteAddress, &store.SessionRecord{Data: session})
}
