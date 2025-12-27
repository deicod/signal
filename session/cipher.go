package session

import (
	"encoding/binary"
	"errors"
	"fmt"

	signalerrors "github.com/deicod/signal/errors"
	"github.com/deicod/signal/ratchet"
	"github.com/deicod/signal/store"
)

// Cipher offers high-level encryption/decryption for a remote address using the legacy envelope format.
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
func (c *Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	record, err := c.loadRecordRequired()
	if err != nil {
		return nil, err
	}
	session := record.Current()

	msg, err := session.CurrentState().Encrypt(plaintext, session.AssociatedData())
	if err != nil {
		return nil, fmt.Errorf("session encrypt: %w", err)
	}

	payload, err := encodeRatchetMessage(msg)
	if err != nil {
		return nil, err
	}

	if err := c.persistRecord(record); err != nil {
		return nil, err
	}
	return encodeEnvelope(envelopeTypeSignal, payload), nil
}

// Decrypt decrypts a ciphertext envelope using either an existing session
// or (in the future) a pre-key bootstrap message.
func (c *Cipher) Decrypt(data []byte) ([]byte, error) {
	msgType, payload, err := decodeEnvelope(data)
	if err != nil {
		return nil, err
	}

	switch msgType {
	case envelopeTypeSignal:
		msg, err := decodeRatchetMessage(payload)
		if err != nil {
			return nil, err
		}
		record, err := c.loadRecordRequired()
		if err != nil {
			return nil, err
		}
		plaintext, err := c.decryptRatchetMessage(record, msg)
		if err != nil {
			return nil, fmt.Errorf("session decrypt: %w", err)
		}

		if err := c.persistRecord(record); err != nil {
			return nil, err
		}
		return plaintext, nil
	case envelopeTypePreKey:
		return c.decryptPreKeyMessage(payload)
	default:
		return nil, fmt.Errorf("%w: unknown message type %d", signalerrors.ErrInvalidMessage, msgType)
	}
}

const (
	envelopeVersion byte = 1

	envelopeTypeSignal byte = 1
	envelopeTypePreKey byte = 2
)

func (c *Cipher) loadRecordRequired() (*Record, error) {
	record, err := c.loadRecordOptional()
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, fmt.Errorf("%w: no session for %v", signalerrors.ErrNoSession, c.remoteAddress)
	}
	return record, nil
}

func (c *Cipher) loadRecordOptional() (*Record, error) {
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

func (c *Cipher) persistRecord(record *Record) error {
	if record == nil || record.Current() == nil {
		return fmt.Errorf("%w: session record is nil", signalerrors.ErrNoSession)
	}
	data, err := record.Serialize()
	if err != nil {
		return fmt.Errorf("%w: serialize session record: %v", signalerrors.ErrInvalidMessage, err)
	}
	return c.store.StoreSession(c.remoteAddress, &store.SessionRecord{Data: data})
}

func encodeEnvelope(msgType byte, payload []byte) []byte {
	out := make([]byte, 1+1+4+len(payload))
	out[0] = envelopeVersion
	out[1] = msgType
	binary.BigEndian.PutUint32(out[2:6], uint32(len(payload)))
	copy(out[6:], payload)
	return out
}

func decodeEnvelope(data []byte) (msgType byte, payload []byte, err error) {
	if len(data) < 6 {
		return 0, nil, fmt.Errorf("%w: session envelope too short", signalerrors.ErrInvalidMessage)
	}
	if data[0] != envelopeVersion {
		return 0, nil, fmt.Errorf("%w: session envelope unsupported version %d", signalerrors.ErrInvalidMessage, data[0])
	}
	msgType = data[1]
	payloadLen := int(binary.BigEndian.Uint32(data[2:6]))
	if payloadLen < 0 || len(data[6:]) != payloadLen {
		return 0, nil, fmt.Errorf("%w: session envelope invalid payload length", signalerrors.ErrInvalidMessage)
	}
	return msgType, data[6:], nil
}

func (c *Cipher) decryptRatchetMessage(record *Record, msg *ratchet.Message) ([]byte, error) {
	if record == nil {
		return nil, fmt.Errorf("%w: missing session record", signalerrors.ErrNoSession)
	}
	if msg == nil {
		return nil, fmt.Errorf("%w: missing ratchet message", signalerrors.ErrInvalidMessage)
	}

	cur := record.Current()
	if cur == nil {
		return nil, fmt.Errorf("%w: missing current session", signalerrors.ErrNoSession)
	}

	plaintext, err := cur.CurrentState().Decrypt(msg, cur.AssociatedData())
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
		plaintext, candErr := candidate.CurrentState().Decrypt(msg, candidate.AssociatedData())
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

func encodeRatchetMessage(msg *ratchet.Message) ([]byte, error) {
	if msg == nil {
		return nil, fmt.Errorf("%w: session signal payload missing ratchet message", signalerrors.ErrInvalidMessage)
	}
	headerBytes := msg.Header.Serialize()
	ciphertext := msg.Ciphertext
	out := make([]byte, len(headerBytes)+4+len(ciphertext))
	copy(out[:len(headerBytes)], headerBytes)
	binary.BigEndian.PutUint32(out[len(headerBytes):len(headerBytes)+4], uint32(len(ciphertext)))
	copy(out[len(headerBytes)+4:], ciphertext)
	return out, nil
}

func decodeRatchetMessage(data []byte) (*ratchet.Message, error) {
	const headerLen = 40
	if len(data) < headerLen+4 {
		return nil, fmt.Errorf("%w: session signal payload too short", signalerrors.ErrInvalidMessage)
	}
	header, err := ratchet.DeserializeHeader(data[:headerLen])
	if err != nil {
		return nil, fmt.Errorf("%w: session signal payload: %v", signalerrors.ErrInvalidMessage, err)
	}
	ctLen := int(binary.BigEndian.Uint32(data[headerLen : headerLen+4]))
	if ctLen < 0 || len(data[headerLen+4:]) != ctLen {
		return nil, fmt.Errorf("%w: session signal payload invalid ciphertext length", signalerrors.ErrInvalidMessage)
	}
	ciphertext := append([]byte(nil), data[headerLen+4:]...)
	return &ratchet.Message{
		Header:     *header,
		Ciphertext: ciphertext,
	}, nil
}
