package wire

import (
	"fmt"

	"google.golang.org/protobuf/encoding/protowire"

	signalerrors "github.com/deicod/signal/errors"
	"github.com/deicod/signal/keys"
)

// PreKeySignalMessage represents a libsignal wire PreKeySignalMessage.
type PreKeySignalMessage struct {
	messageVersion  uint8
	registrationID  uint32
	preKeyID        *uint32
	signedPreKeyID  uint32
	kyberPreKeyID   *uint32
	kyberCiphertext []byte
	baseKey         [32]byte
	identityKey     keys.IdentityKey
	message         *SignalMessage
	serialized      []byte
}

// NewPreKeySignalMessage constructs and serializes a PreKeySignalMessage.
func NewPreKeySignalMessage(
	messageVersion uint8,
	registrationID uint32,
	preKeyID *uint32,
	signedPreKeyID uint32,
	kyberPreKeyID *uint32,
	kyberCiphertext []byte,
	baseKey [32]byte,
	identityKey keys.IdentityKey,
	message *SignalMessage,
) (*PreKeySignalMessage, error) {
	if message == nil {
		return nil, fmt.Errorf("%w: missing inner signal message", signalerrors.ErrInvalidMessage)
	}
	if messageVersion < ciphertextMessagePreKyberVersion || messageVersion > ciphertextMessageCurrentVersion {
		return nil, fmt.Errorf("%w: unsupported pre-key version %d", signalerrors.ErrInvalidMessage, messageVersion)
	}
	if messageVersion > ciphertextMessagePreKyberVersion && (kyberPreKeyID == nil || len(kyberCiphertext) == 0) {
		return nil, fmt.Errorf("%w: kyber payload required for version %d", signalerrors.ErrInvalidMessage, messageVersion)
	}
	if (kyberPreKeyID == nil) != (len(kyberCiphertext) == 0) {
		return nil, fmt.Errorf("%w: kyber pre-key id/ciphertext mismatch", signalerrors.ErrInvalidMessage)
	}

	body := encodePreKeySignalMessageBody(registrationID, preKeyID, signedPreKeyID, kyberPreKeyID, kyberCiphertext, baseKey, identityKey, message)
	serialized := make([]byte, 0, 1+len(body))
	serialized = append(serialized, versionByte(messageVersion, ciphertextMessageCurrentVersion))
	serialized = append(serialized, body...)

	return &PreKeySignalMessage{
		messageVersion:  messageVersion,
		registrationID:  registrationID,
		preKeyID:        preKeyID,
		signedPreKeyID:  signedPreKeyID,
		kyberPreKeyID:   kyberPreKeyID,
		kyberCiphertext: append([]byte(nil), kyberCiphertext...),
		baseKey:         baseKey,
		identityKey:     identityKey,
		message:         message,
		serialized:      serialized,
	}, nil
}

// ParsePreKeySignalMessage deserializes a PreKeySignalMessage from wire bytes.
func ParsePreKeySignalMessage(data []byte) (*PreKeySignalMessage, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("%w: pre-key message too short", signalerrors.ErrInvalidMessage)
	}
	messageVersion := parseMessageVersion(data[0])
	if messageVersion < ciphertextMessagePreKyberVersion {
		return nil, fmt.Errorf("%w: legacy pre-key message version %d", signalerrors.ErrInvalidMessage, messageVersion)
	}
	if messageVersion > ciphertextMessageCurrentVersion {
		return nil, fmt.Errorf("%w: unsupported pre-key message version %d", signalerrors.ErrInvalidMessage, messageVersion)
	}

	regID, preKeyID, signedPreKeyID, kyberPreKeyID, kyberCiphertext, baseKey, identityKey, message, err := decodePreKeySignalMessageBody(data[1:])
	if err != nil {
		return nil, err
	}

	if messageVersion > ciphertextMessagePreKyberVersion {
		if kyberPreKeyID == nil || len(kyberCiphertext) == 0 {
			return nil, fmt.Errorf("%w: kyber payload required for version %d", signalerrors.ErrInvalidMessage, messageVersion)
		}
	}

	return &PreKeySignalMessage{
		messageVersion:  messageVersion,
		registrationID:  regID,
		preKeyID:        preKeyID,
		signedPreKeyID:  signedPreKeyID,
		kyberPreKeyID:   kyberPreKeyID,
		kyberCiphertext: kyberCiphertext,
		baseKey:         baseKey,
		identityKey:     identityKey,
		message:         message,
		serialized:      append([]byte(nil), data...),
	}, nil
}

// MessageVersion returns the high-nibble message version.
func (m *PreKeySignalMessage) MessageVersion() uint8 {
	if m == nil {
		return 0
	}
	return m.messageVersion
}

// RegistrationID returns the sender registration ID.
func (m *PreKeySignalMessage) RegistrationID() uint32 {
	if m == nil {
		return 0
	}
	return m.registrationID
}

// PreKeyID returns the optional pre-key ID.
func (m *PreKeySignalMessage) PreKeyID() *uint32 {
	if m == nil || m.preKeyID == nil {
		return nil
	}
	id := *m.preKeyID
	return &id
}

// SignedPreKeyID returns the signed pre-key ID.
func (m *PreKeySignalMessage) SignedPreKeyID() uint32 {
	if m == nil {
		return 0
	}
	return m.signedPreKeyID
}

// KyberPreKeyID returns the optional Kyber pre-key ID.
func (m *PreKeySignalMessage) KyberPreKeyID() *uint32 {
	if m == nil || m.kyberPreKeyID == nil {
		return nil
	}
	id := *m.kyberPreKeyID
	return &id
}

// KyberCiphertext returns the Kyber ciphertext payload.
func (m *PreKeySignalMessage) KyberCiphertext() []byte {
	if m == nil {
		return nil
	}
	return append([]byte(nil), m.kyberCiphertext...)
}

// BaseKey returns the initiator base key.
func (m *PreKeySignalMessage) BaseKey() [32]byte {
	if m == nil {
		return [32]byte{}
	}
	return m.baseKey
}

// IdentityKey returns the initiator identity key.
func (m *PreKeySignalMessage) IdentityKey() keys.IdentityKey {
	if m == nil {
		return keys.IdentityKey{}
	}
	return m.identityKey
}

// Message returns the embedded SignalMessage.
func (m *PreKeySignalMessage) Message() *SignalMessage {
	if m == nil {
		return nil
	}
	return m.message
}

// Serialize returns the wire encoding.
func (m *PreKeySignalMessage) Serialize() []byte {
	if m == nil {
		return nil
	}
	return append([]byte(nil), m.serialized...)
}

func encodePreKeySignalMessageBody(
	registrationID uint32,
	preKeyID *uint32,
	signedPreKeyID uint32,
	kyberPreKeyID *uint32,
	kyberCiphertext []byte,
	baseKey [32]byte,
	identityKey keys.IdentityKey,
	message *SignalMessage,
) []byte {
	out := make([]byte, 0, 128+len(message.serialized))

	// Field order matches libsignal's proto declaration.
	out = protowire.AppendTag(out, 5, protowire.VarintType)
	out = protowire.AppendVarint(out, uint64(registrationID))

	if preKeyID != nil {
		out = protowire.AppendTag(out, 1, protowire.VarintType)
		out = protowire.AppendVarint(out, uint64(*preKeyID))
	}

	out = protowire.AppendTag(out, 6, protowire.VarintType)
	out = protowire.AppendVarint(out, uint64(signedPreKeyID))

	if kyberPreKeyID != nil && len(kyberCiphertext) > 0 {
		out = protowire.AppendTag(out, 7, protowire.VarintType)
		out = protowire.AppendVarint(out, uint64(*kyberPreKeyID))
		out = protowire.AppendTag(out, 8, protowire.BytesType)
		out = protowire.AppendBytes(out, kyberCiphertext)
	}

	out = protowire.AppendTag(out, 2, protowire.BytesType)
	out = protowire.AppendBytes(out, keys.SerializeWirePublicKey(baseKey))

	out = protowire.AppendTag(out, 3, protowire.BytesType)
	out = protowire.AppendBytes(out, keys.SerializeWirePublicKey(identityKey.PublicKey))

	out = protowire.AppendTag(out, 4, protowire.BytesType)
	out = protowire.AppendBytes(out, message.serialized)

	return out
}

func decodePreKeySignalMessageBody(data []byte) (registrationID uint32, preKeyID *uint32, signedPreKeyID uint32, kyberPreKeyID *uint32, kyberCiphertext []byte, baseKey [32]byte, identityKey keys.IdentityKey, message *SignalMessage, err error) {
	var (
		gotBaseKey        bool
		gotIdentityKey    bool
		gotMessage        bool
		gotSignedPreKeyID bool
	)

	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return 0, nil, 0, nil, nil, baseKey, identityKey, nil, fmt.Errorf("%w: pre-key tag", signalerrors.ErrInvalidMessage)
		}
		data = data[n:]
		switch num {
		case 5: // registration_id
			if typ != protowire.VarintType {
				return 0, nil, 0, nil, nil, baseKey, identityKey, nil, fmt.Errorf("%w: pre-key registration id type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return 0, nil, 0, nil, nil, baseKey, identityKey, nil, fmt.Errorf("%w: pre-key registration id", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
			registrationID = uint32(val)
		case 1: // pre_key_id
			if typ != protowire.VarintType {
				return 0, nil, 0, nil, nil, baseKey, identityKey, nil, fmt.Errorf("%w: pre-key id type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return 0, nil, 0, nil, nil, baseKey, identityKey, nil, fmt.Errorf("%w: pre-key id", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
			id := uint32(val)
			preKeyID = &id
		case 6: // signed_pre_key_id
			if typ != protowire.VarintType {
				return 0, nil, 0, nil, nil, baseKey, identityKey, nil, fmt.Errorf("%w: signed pre-key id type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return 0, nil, 0, nil, nil, baseKey, identityKey, nil, fmt.Errorf("%w: signed pre-key id", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
			signedPreKeyID = uint32(val)
			gotSignedPreKeyID = true
		case 7: // kyber_pre_key_id
			if typ != protowire.VarintType {
				return 0, nil, 0, nil, nil, baseKey, identityKey, nil, fmt.Errorf("%w: kyber pre-key id type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return 0, nil, 0, nil, nil, baseKey, identityKey, nil, fmt.Errorf("%w: kyber pre-key id", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
			id := uint32(val)
			kyberPreKeyID = &id
		case 8: // kyber_ciphertext
			if typ != protowire.BytesType {
				return 0, nil, 0, nil, nil, baseKey, identityKey, nil, fmt.Errorf("%w: kyber ciphertext type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return 0, nil, 0, nil, nil, baseKey, identityKey, nil, fmt.Errorf("%w: kyber ciphertext", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
			kyberCiphertext = append([]byte(nil), val...)
		case 2: // base_key
			if typ != protowire.BytesType {
				return 0, nil, 0, nil, nil, baseKey, identityKey, nil, fmt.Errorf("%w: base key type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return 0, nil, 0, nil, nil, baseKey, identityKey, nil, fmt.Errorf("%w: base key", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
			key, err := keys.DeserializeWirePublicKey(val)
			if err != nil {
				return 0, nil, 0, nil, nil, baseKey, identityKey, nil, err
			}
			baseKey = key
			gotBaseKey = true
		case 3: // identity_key
			if typ != protowire.BytesType {
				return 0, nil, 0, nil, nil, baseKey, identityKey, nil, fmt.Errorf("%w: identity key type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return 0, nil, 0, nil, nil, baseKey, identityKey, nil, fmt.Errorf("%w: identity key", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
			key, err := keys.DeserializeWirePublicKey(val)
			if err != nil {
				return 0, nil, 0, nil, nil, baseKey, identityKey, nil, err
			}
			identityKey = keys.IdentityKey{PublicKey: key}
			gotIdentityKey = true
		case 4: // message
			if typ != protowire.BytesType {
				return 0, nil, 0, nil, nil, baseKey, identityKey, nil, fmt.Errorf("%w: signal message type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return 0, nil, 0, nil, nil, baseKey, identityKey, nil, fmt.Errorf("%w: signal message", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
			msg, err := ParseSignalMessage(val)
			if err != nil {
				return 0, nil, 0, nil, nil, baseKey, identityKey, nil, err
			}
			message = msg
			gotMessage = true
		default:
			n := protowire.ConsumeFieldValue(num, typ, data)
			if n < 0 {
				return 0, nil, 0, nil, nil, baseKey, identityKey, nil, fmt.Errorf("%w: pre-key field", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
		}
	}

	if !gotBaseKey || !gotIdentityKey || !gotMessage || !gotSignedPreKeyID {
		return 0, nil, 0, nil, nil, baseKey, identityKey, nil, fmt.Errorf("%w: pre-key message missing fields", signalerrors.ErrInvalidMessage)
	}
	if (kyberPreKeyID == nil) != (len(kyberCiphertext) == 0) {
		return 0, nil, 0, nil, nil, baseKey, identityKey, nil, fmt.Errorf("%w: kyber payload mismatch", signalerrors.ErrInvalidMessage)
	}
	return registrationID, preKeyID, signedPreKeyID, kyberPreKeyID, kyberCiphertext, baseKey, identityKey, message, nil
}
