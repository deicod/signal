package session

import (
	"errors"
	"fmt"

	signalerrors "github.com/deicod/signal/errors"
	"github.com/deicod/signal/keys"
	"github.com/deicod/signal/x3dh"
)

// EncryptWithPreKeyBundle bootstraps a new session using the recipient's pre-key bundle
// and returns a single ciphertext envelope containing the X3DH initial message and the
// first Double Ratchet ciphertext.
//
// This method should only be used when no existing session is present for the remote
// address.
func (c *Cipher) EncryptWithPreKeyBundle(bundle *keys.PreKeyBundle, plaintext []byte) ([]byte, error) {
	if c == nil || c.store == nil {
		return nil, fmt.Errorf("session cipher not initialized")
	}
	if c.store.ContainsSession(c.remoteAddress) {
		return nil, fmt.Errorf("%w: session already exists for %v", signalerrors.ErrStaleKeyExchange, c.remoteAddress)
	}

	session, msg, err := c.builder.ProcessPreKeyBundle(bundle)
	if err != nil {
		return nil, err
	}

	ratchetMsg, err := session.CurrentState().Encrypt(plaintext, session.AssociatedData())
	if err != nil {
		return nil, fmt.Errorf("session encrypt: %w", err)
	}
	signalPayload, err := encodeRatchetMessage(ratchetMsg)
	if err != nil {
		return nil, err
	}
	msg.Ciphertext = signalPayload

	record, err := NewRecord(session, DefaultMaxArchivedSessions)
	if err != nil {
		return nil, err
	}
	if err := c.persistRecord(record); err != nil {
		return nil, err
	}

	preKeyPayload, err := msg.Serialize()
	if err != nil {
		return nil, fmt.Errorf("%w: serialize x3dh message: %v", signalerrors.ErrInvalidMessage, err)
	}
	return encodeEnvelope(envelopeTypePreKey, preKeyPayload), nil
}

func (c *Cipher) decryptPreKeyMessage(payload []byte) ([]byte, error) {
	if c == nil || c.store == nil {
		return nil, fmt.Errorf("session cipher not initialized")
	}

	msg, err := x3dh.DeserializeMessage(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", signalerrors.ErrInvalidMessage, err)
	}
	if len(msg.Ciphertext) == 0 {
		return nil, fmt.Errorf("%w: pre-key message missing ciphertext", signalerrors.ErrInvalidMessage)
	}

	ratchetMsg, err := decodeRatchetMessage(msg.Ciphertext)
	if err != nil {
		return nil, err
	}

	record, err := c.loadRecordOptional()
	if err != nil {
		return nil, err
	}
	if record != nil {
		plaintext, err := c.decryptRatchetMessage(record, ratchetMsg)
		if err == nil {
			if err := c.persistRecord(record); err != nil {
				return nil, err
			}
			return plaintext, nil
		}
		if errors.Is(err, signalerrors.ErrDuplicateMessage) {
			return nil, fmt.Errorf("session decrypt: %w", err)
		}
	}

	session, _, err := c.builder.ProcessPreKeyMessage(msg)
	if err != nil {
		return nil, err
	}

	plaintext, err := session.CurrentState().Decrypt(ratchetMsg, session.AssociatedData())
	if err != nil {
		return nil, fmt.Errorf("session decrypt: %w", err)
	}

	if record == nil {
		record, err = NewRecord(session, DefaultMaxArchivedSessions)
		if err != nil {
			return nil, err
		}
	} else {
		if err := record.Promote(session); err != nil {
			return nil, err
		}
	}
	if err := c.persistRecord(record); err != nil {
		return nil, err
	}

	return plaintext, nil
}
