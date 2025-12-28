package session

import (
	"errors"
	"fmt"

	signalcrypto "github.com/deicod/signal/crypto"
	signalerrors "github.com/deicod/signal/errors"
	"github.com/deicod/signal/keys"
	wire "github.com/deicod/signal/protocol/wire"
	"github.com/deicod/signal/ratchet"
	"github.com/deicod/signal/spqr"
	"github.com/deicod/signal/store"
	"github.com/deicod/signal/x3dh"
)

// WireCipher offers high-level encryption/decryption targeting libsignal wire formats.
type WireCipher struct {
	store         store.ProtocolStore
	remoteAddress store.Address
	builder       *Builder
}

// NewWireCipher builds a wire-compatible cipher bound to a ProtocolStore and remote address.
func NewWireCipher(s store.ProtocolStore, addr store.Address) *WireCipher {
	return &WireCipher{
		store:         s,
		remoteAddress: addr,
		builder:       NewBuilder(s, addr),
	}
}

// Encrypt uses the current session to encrypt plaintext. A session must exist in the store.
func (c *WireCipher) Encrypt(plaintext []byte) ([]byte, error) {
	record, err := c.loadRecordRequired()
	if err != nil {
		return nil, err
	}
	session := record.Current()

	msg, err := c.encryptSignalMessage(session, plaintext)
	if err != nil {
		return nil, fmt.Errorf("session encrypt: %w", err)
	}

	if err := c.persistRecord(record); err != nil {
		return nil, err
	}
	return msg.Serialize(), nil
}

// Decrypt decrypts a ciphertext using either an existing session or a pre-key bootstrap message.
func (c *WireCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	record, err := c.loadRecordOptional()
	if err != nil {
		return nil, err
	}

	if msg, err := wire.ParseSignalMessage(ciphertext); err == nil {
		if record == nil {
			return nil, fmt.Errorf("%w: no session for %v", signalerrors.ErrNoSession, c.remoteAddress)
		}
		plaintext, err := c.decryptSignalMessage(record, msg)
		if err != nil {
			return nil, fmt.Errorf("session decrypt: %w", err)
		}
		if err := c.persistRecord(record); err != nil {
			return nil, err
		}
		return plaintext, nil
	}

	preKeyMsg, err := wire.ParsePreKeySignalMessage(ciphertext)
	if err != nil {
		return nil, err
	}
	return c.decryptPreKeyMessage(record, preKeyMsg)
}

// EncryptWithPreKeyBundle bootstraps a new session using the recipient's pre-key bundle.
func (c *WireCipher) EncryptWithPreKeyBundle(bundle *keys.PreKeyBundle, plaintext []byte) ([]byte, error) {
	if c == nil || c.store == nil {
		return nil, fmt.Errorf("session cipher not initialized")
	}
	if c.store.ContainsSession(c.remoteAddress) {
		return nil, fmt.Errorf("%w: session already exists for %v", signalerrors.ErrStaleKeyExchange, c.remoteAddress)
	}

	session, x3msg, err := c.builder.ProcessPreKeyBundle(bundle)
	if err != nil {
		return nil, err
	}

	signalMsg, err := c.encryptSignalMessage(session, plaintext)
	if err != nil {
		return nil, fmt.Errorf("session encrypt: %w", err)
	}

	registrationID, err := c.store.GetLocalRegistrationID()
	if err != nil {
		return nil, fmt.Errorf("load registration id: %w", err)
	}

	preKeyMsg, err := wire.NewPreKeySignalMessage(
		ciphertextVersionForSession(session),
		registrationID,
		x3msg.PreKeyID,
		x3msg.SignedPreKeyID,
		x3msg.KyberPreKeyID,
		x3msg.KyberCiphertext,
		x3msg.EphemeralKey,
		x3msg.IdentityKey,
		signalMsg,
	)
	if err != nil {
		return nil, err
	}

	record, err := NewRecord(session, DefaultMaxArchivedSessions)
	if err != nil {
		return nil, err
	}
	if err := c.persistRecord(record); err != nil {
		return nil, err
	}

	return preKeyMsg.Serialize(), nil
}

func (c *WireCipher) encryptSignalMessage(session *Session, plaintext []byte) (*wire.SignalMessage, error) {
	if session == nil {
		return nil, fmt.Errorf("%w: missing session", signalerrors.ErrNoSession)
	}

	state := session.CurrentState()
	header, mk, err := state.NextSendingMessageKey()
	if err != nil {
		return nil, err
	}

	var pqRatchet []byte
	var salt []byte
	if session.pqrState != nil {
		pqrNext := session.pqrState.Clone()
		if pqrNext == nil {
			return nil, spqr.ErrStateDecode
		}
		pqRatchet, salt, err = pqrNext.Send()
		if err != nil {
			return nil, err
		}
		session.pqrState = pqrNext
	}

	encKey, macKey, iv := ratchet.DeriveMessageKeysWithSalt(mk, salt)
	signalcrypto.ZeroBytes(mk[:])
	signalcrypto.ZeroBytes(salt)
	defer signalcrypto.ZeroBytes(encKey)
	defer signalcrypto.ZeroBytes(macKey)
	defer signalcrypto.ZeroBytes(iv)
	ciphertext, err := signalcrypto.AESCBCEncrypt(encKey, iv, plaintext)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	if session.localIdentity == nil || session.remoteIdentity == nil {
		return nil, fmt.Errorf("%w: missing identity keys", signalerrors.ErrInvalidKey)
	}

	messageVersion := ciphertextVersionForSession(session)
	return wire.NewSignalMessage(
		messageVersion,
		macKey,
		header.DH,
		header.N,
		header.PN,
		ciphertext,
		*session.localIdentity,
		*session.remoteIdentity,
		pqRatchet,
	)
}

func (c *WireCipher) decryptSignalMessage(record *Record, msg *wire.SignalMessage) ([]byte, error) {
	if record == nil {
		return nil, fmt.Errorf("%w: missing session record", signalerrors.ErrNoSession)
	}
	if msg == nil {
		return nil, fmt.Errorf("%w: missing signal message", signalerrors.ErrInvalidMessage)
	}

	cur := record.Current()
	if cur == nil {
		return nil, fmt.Errorf("%w: missing current session", signalerrors.ErrNoSession)
	}

	plaintext, err := decryptSignalWithSession(cur, msg)
	if err == nil {
		return plaintext, nil
	}
	if errors.Is(err, signalerrors.ErrDuplicateMessage) {
		return nil, err
	}

	for _, candidate := range record.Previous() {
		if candidate == nil {
			continue
		}
		plaintext, candErr := decryptSignalWithSession(candidate, msg)
		if candErr == nil {
			if err := record.Promote(candidate); err != nil {
				return nil, err
			}
			return plaintext, nil
		}
		if errors.Is(candErr, signalerrors.ErrDuplicateMessage) {
			return nil, candErr
		}
	}

	return nil, err
}

func decryptSignalWithSession(session *Session, msg *wire.SignalMessage) ([]byte, error) {
	if session == nil {
		return nil, fmt.Errorf("%w: missing session", signalerrors.ErrNoSession)
	}
	if msg == nil {
		return nil, fmt.Errorf("%w: missing signal message", signalerrors.ErrInvalidMessage)
	}
	if session.localIdentity == nil || session.remoteIdentity == nil {
		return nil, fmt.Errorf("%w: missing identity keys", signalerrors.ErrInvalidKey)
	}

	msgVersion := msg.MessageVersion()
	sessionVersion, hasSessionVersion := normalizeCiphertextVersion(session.version)
	if hasSessionVersion && msgVersion != sessionVersion {
		return nil, fmt.Errorf("%w: message version %d does not match session", signalerrors.ErrInvalidMessage, msgVersion)
	}

	state := session.CurrentState()
	if state == nil {
		return nil, fmt.Errorf("%w: missing ratchet state", signalerrors.ErrNoSession)
	}

	header := ratchet.Header{
		DH: msg.SenderRatchetKey(),
		PN: msg.PreviousCounter(),
		N:  msg.Counter(),
	}

	next := state.Clone()
	mk, err := next.AdvanceForHeader(&header)
	if err != nil {
		return nil, err
	}

	pqRatchet := msg.PQRatchet()
	var salt []byte
	var pqrNext *spqr.State
	if session.pqrState != nil {
		pqrNext = session.pqrState.Clone()
		if pqrNext == nil {
			return nil, spqr.ErrStateDecode
		}
		salt, err = pqrNext.Receive(pqRatchet)
		if err != nil {
			return nil, err
		}
	} else if len(pqRatchet) > 0 {
		return nil, fmt.Errorf("%w: missing pq ratchet state", signalerrors.ErrInvalidMessage)
	}

	encKey, macKey, iv := ratchet.DeriveMessageKeysWithSalt(*mk, salt)
	signalcrypto.ZeroBytes(salt)
	defer signalcrypto.ZeroKey(mk)
	defer signalcrypto.ZeroBytes(encKey)
	defer signalcrypto.ZeroBytes(macKey)
	defer signalcrypto.ZeroBytes(iv)
	ok, err := msg.VerifyMAC(*session.remoteIdentity, *session.localIdentity, macKey)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%w: invalid mac", signalerrors.ErrInvalidMAC)
	}

	plaintext, err := signalcrypto.AESCBCDecrypt(encKey, iv, msg.Ciphertext())
	if err != nil {
		return nil, errors.Join(signalerrors.ErrInvalidMAC, fmt.Errorf("decrypt: %w", err))
	}

	if !hasSessionVersion {
		setSessionCiphertextVersion(session, msgVersion)
	}
	*state = *next
	if pqrNext != nil {
		session.pqrState = pqrNext
	}
	return plaintext, nil
}

func (c *WireCipher) decryptPreKeyMessage(record *Record, msg *wire.PreKeySignalMessage) ([]byte, error) {
	if c == nil || c.store == nil {
		return nil, fmt.Errorf("session cipher not initialized")
	}
	if msg == nil {
		return nil, fmt.Errorf("%w: pre-key message missing", signalerrors.ErrInvalidMessage)
	}
	if record != nil {
		plaintext, err := c.decryptSignalMessage(record, msg.Message())
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

	x3msg := &x3dh.Message{
		IdentityKey:     msg.IdentityKey(),
		EphemeralKey:    msg.BaseKey(),
		PreKeyID:        msg.PreKeyID(),
		SignedPreKeyID:  msg.SignedPreKeyID(),
		KyberPreKeyID:   msg.KyberPreKeyID(),
		KyberCiphertext: msg.KyberCiphertext(),
		Ciphertext:      msg.Message().Serialize(),
	}

	session, _, err := c.builder.ProcessPreKeyMessage(x3msg)
	if err != nil {
		return nil, err
	}

	plaintext, err := decryptSignalWithSession(session, msg.Message())
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

func (c *WireCipher) loadRecordRequired() (*Record, error) {
	record, err := c.loadRecordOptional()
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, fmt.Errorf("%w: no session for %v", signalerrors.ErrNoSession, c.remoteAddress)
	}
	return record, nil
}

func (c *WireCipher) loadRecordOptional() (*Record, error) {
	rec, err := c.store.LoadSession(c.remoteAddress)
	if err != nil {
		return nil, fmt.Errorf("load session record: %w", err)
	}
	if rec == nil || len(rec.Data) == 0 {
		return nil, nil
	}
	record, err := DeserializeRecord(rec.Data)
	if err != nil {
		return nil, fmt.Errorf("%w: deserialize session record: %v", signalerrors.ErrInvalidMessage, err)
	}
	if record.Current() == nil {
		return nil, fmt.Errorf("%w: invalid session record for %v", signalerrors.ErrInvalidMessage, c.remoteAddress)
	}
	return record, nil
}

func (c *WireCipher) persistRecord(record *Record) error {
	if record == nil || record.Current() == nil {
		return fmt.Errorf("%w: session record is nil", signalerrors.ErrNoSession)
	}
	data, err := record.Serialize()
	if err != nil {
		return fmt.Errorf("%w: serialize session record: %v", signalerrors.ErrInvalidMessage, err)
	}
	if err := c.store.StoreSession(c.remoteAddress, &store.SessionRecord{Data: data}); err != nil {
		return err
	}
	if err := c.store.EnforceSessionLimit(c.remoteAddress); err != nil {
		return fmt.Errorf("enforce session limit: %w", err)
	}
	return nil
}
