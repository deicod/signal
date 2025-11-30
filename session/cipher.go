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

// Cipher offers high-level encryption/decryption for a remote address.
type Cipher struct {
	store         store.ProtocolStore
	remoteAddress store.Address
	builder       *Builder
}

// NewCipher builds a cipher bound to a ProtocolStore and remote address.
func NewCipher(s store.ProtocolStore, addr store.Address) *Cipher {
	return &Cipher{
		store:         s,
		remoteAddress: addr,
		builder:       NewBuilder(s, addr),
	}
}

// Encrypt uses the current session to encrypt plaintext. A session must exist in the store.
func (c *Cipher) Encrypt(plaintext []byte) (*SignalCiphertext, error) {
	session, record, err := c.loadSession()
	if err != nil {
		return nil, err
	}

	msg, err := session.CurrentState().Encrypt(plaintext, session.AssociatedData())
	if err != nil {
		return nil, fmt.Errorf("session encrypt: %w", err)
	}

	if err := c.saveSession(session, record); err != nil {
		return nil, err
	}
	return &SignalCiphertext{Message: msg}, nil
}

// Decrypt decrypts a ciphertext message using the current session.
func (c *Cipher) Decrypt(message CiphertextMessage) ([]byte, error) {
	session, record, err := c.loadSession()
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

	if err := c.saveSession(session, record); err != nil {
		return nil, err
	}
	return plaintext, nil
}

func (c *Cipher) loadSession() (*Session, *Record, error) {
	record, err := c.store.LoadSession(c.remoteAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("load session: %w", err)
	}
	if record == nil || record.Data == nil {
		return nil, nil, fmt.Errorf("no session for %v", c.remoteAddress)
	}
	switch data := record.Data.(type) {
	case *Record:
		if data.Current() == nil {
			return nil, nil, fmt.Errorf("invalid session record for %v", c.remoteAddress)
		}
		return data.Current(), data, nil
	case *Session:
		if data == nil {
			return nil, nil, fmt.Errorf("invalid session record for %v", c.remoteAddress)
		}
		return data, nil, nil
	default:
		return nil, nil, fmt.Errorf("invalid session record for %v", c.remoteAddress)
	}
}

func (c *Cipher) saveSession(session *Session, record *Record) error {
	if session == nil {
		return fmt.Errorf("session is nil")
	}
	if record == nil {
		var err error
		record, err = NewRecord(session, DefaultMaxArchivedSessions)
		if err != nil {
			return err
		}
	} else {
		if err := record.Promote(session); err != nil {
			return err
		}
	}
	return c.store.StoreSession(c.remoteAddress, &store.SessionRecord{Data: record})
}
