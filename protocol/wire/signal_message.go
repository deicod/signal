package wire

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"

	"google.golang.org/protobuf/encoding/protowire"

	signalerrors "github.com/deicod/signal/errors"
	"github.com/deicod/signal/keys"
)

// SignalMessage represents a libsignal wire SignalMessage.
type SignalMessage struct {
	messageVersion  uint8
	senderRatchet   [32]byte
	counter         uint32
	previousCounter uint32
	ciphertext      []byte
	pqRatchet       []byte
	serialized      []byte
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
	if messageVersion < CiphertextMessagePreKyberVersion || messageVersion > CiphertextMessageCurrentVersion {
		return nil, fmt.Errorf("%w: unsupported message version %d", signalerrors.ErrInvalidMessage, messageVersion)
	}
	body := encodeSignalMessageBody(senderRatchet, counter, previousCounter, ciphertext, pqRatchet)
	serialized := make([]byte, 0, 1+len(body)+SignalMessageMACLength)
	serialized = append(serialized, versionByte(messageVersion, CiphertextMessageCurrentVersion))
	serialized = append(serialized, body...)

	mac, err := computeSignalMAC(macKey, senderIdentity, receiverIdentity, serialized)
	if err != nil {
		return nil, err
	}
	serialized = append(serialized, mac...)

	return &SignalMessage{
		messageVersion:  messageVersion,
		senderRatchet:   senderRatchet,
		counter:         counter,
		previousCounter: previousCounter,
		ciphertext:      append([]byte(nil), ciphertext...),
		pqRatchet:       append([]byte(nil), pqRatchet...),
		serialized:      serialized,
	}, nil
}

// ParseSignalMessage deserializes a SignalMessage from wire bytes.
func ParseSignalMessage(data []byte) (*SignalMessage, error) {
	if len(data) < 1+SignalMessageMACLength {
		return nil, fmt.Errorf("%w: signal message too short", signalerrors.ErrInvalidMessage)
	}
	messageVersion := parseMessageVersion(data[0])
	if messageVersion < CiphertextMessagePreKyberVersion {
		return nil, fmt.Errorf("%w: legacy signal message version %d", signalerrors.ErrInvalidMessage, messageVersion)
	}
	if messageVersion > CiphertextMessageCurrentVersion {
		return nil, fmt.Errorf("%w: unsupported signal message version %d", signalerrors.ErrInvalidMessage, messageVersion)
	}

	body := data[1 : len(data)-SignalMessageMACLength]
	senderRatchet, counter, previousCounter, ciphertext, pqRatchet, err := decodeSignalMessageBody(body)
	if err != nil {
		return nil, err
	}

	return &SignalMessage{
		messageVersion:  messageVersion,
		senderRatchet:   senderRatchet,
		counter:         counter,
		previousCounter: previousCounter,
		ciphertext:      ciphertext,
		pqRatchet:       pqRatchet,
		serialized:      append([]byte(nil), data...),
	}, nil
}

// MessageVersion returns the high-nibble message version.
func (m *SignalMessage) MessageVersion() uint8 {
	if m == nil {
		return 0
	}
	return m.messageVersion
}

// SenderRatchetKey returns the sender ratchet public key (Curve25519).
func (m *SignalMessage) SenderRatchetKey() [32]byte {
	if m == nil {
		return [32]byte{}
	}
	return m.senderRatchet
}

// Counter returns the message counter.
func (m *SignalMessage) Counter() uint32 {
	if m == nil {
		return 0
	}
	return m.counter
}

// PreviousCounter returns the previous chain counter.
func (m *SignalMessage) PreviousCounter() uint32 {
	if m == nil {
		return 0
	}
	return m.previousCounter
}

// Ciphertext returns a copy of the message ciphertext.
func (m *SignalMessage) Ciphertext() []byte {
	if m == nil {
		return nil
	}
	return append([]byte(nil), m.ciphertext...)
}

// PQRatchet returns the optional PQ ratchet payload.
func (m *SignalMessage) PQRatchet() []byte {
	if m == nil {
		return nil
	}
	return append([]byte(nil), m.pqRatchet...)
}

// Serialize returns the wire encoding (including MAC).
func (m *SignalMessage) Serialize() []byte {
	if m == nil {
		return nil
	}
	return append([]byte(nil), m.serialized...)
}

// VerifyMAC validates the MAC against the provided identities and mac key.
func (m *SignalMessage) VerifyMAC(senderIdentity keys.IdentityKey, receiverIdentity keys.IdentityKey, macKey []byte) (bool, error) {
	if m == nil {
		return false, fmt.Errorf("%w: signal message is nil", signalerrors.ErrInvalidMessage)
	}
	if len(m.serialized) < SignalMessageMACLength {
		return false, fmt.Errorf("%w: signal message too short", signalerrors.ErrInvalidMessage)
	}
	mac, err := computeSignalMAC(macKey, senderIdentity, receiverIdentity, m.serialized[:len(m.serialized)-SignalMessageMACLength])
	if err != nil {
		return false, err
	}
	remoteMac := m.serialized[len(m.serialized)-SignalMessageMACLength:]
	return hmac.Equal(remoteMac, mac), nil
}

func computeSignalMAC(macKey []byte, senderIdentity keys.IdentityKey, receiverIdentity keys.IdentityKey, message []byte) ([]byte, error) {
	if len(macKey) != 32 {
		return nil, fmt.Errorf("%w: mac key length %d", signalerrors.ErrInvalidKey, len(macKey))
	}
	mac := hmac.New(sha256.New, macKey)
	mac.Write(keys.SerializeWirePublicKey(senderIdentity.PublicKey))
	mac.Write(keys.SerializeWirePublicKey(receiverIdentity.PublicKey))
	mac.Write(message)
	sum := mac.Sum(nil)
	return append([]byte(nil), sum[:SignalMessageMACLength]...), nil
}

func encodeSignalMessageBody(senderRatchet [32]byte, counter uint32, previousCounter uint32, ciphertext []byte, pqRatchet []byte) []byte {
	out := make([]byte, 0, 128+len(ciphertext)+len(pqRatchet))
	out = protowire.AppendTag(out, 1, protowire.BytesType)
	out = protowire.AppendBytes(out, keys.SerializeWirePublicKey(senderRatchet))
	out = protowire.AppendTag(out, 2, protowire.VarintType)
	out = protowire.AppendVarint(out, uint64(counter))
	out = protowire.AppendTag(out, 3, protowire.VarintType)
	out = protowire.AppendVarint(out, uint64(previousCounter))
	out = protowire.AppendTag(out, 4, protowire.BytesType)
	out = protowire.AppendBytes(out, ciphertext)
	if len(pqRatchet) > 0 {
		out = protowire.AppendTag(out, 5, protowire.BytesType)
		out = protowire.AppendBytes(out, pqRatchet)
	}
	return out
}

func decodeSignalMessageBody(body []byte) (senderRatchet [32]byte, counter uint32, previousCounter uint32, ciphertext []byte, pqRatchet []byte, err error) {
	var (
		gotRatchet    bool
		gotCounter    bool
		gotCiphertext bool
	)

	for len(body) > 0 {
		num, typ, n := protowire.ConsumeTag(body)
		if n < 0 {
			return senderRatchet, 0, 0, nil, nil, fmt.Errorf("%w: signal message tag", signalerrors.ErrInvalidMessage)
		}
		body = body[n:]
		switch num {
		case 1: // ratchet_key
			if typ != protowire.BytesType {
				return senderRatchet, 0, 0, nil, nil, fmt.Errorf("%w: signal ratchet key type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeBytes(body)
			if n < 0 {
				return senderRatchet, 0, 0, nil, nil, fmt.Errorf("%w: signal ratchet key", signalerrors.ErrInvalidMessage)
			}
			body = body[n:]
			key, err := keys.DeserializeWirePublicKey(val)
			if err != nil {
				return senderRatchet, 0, 0, nil, nil, err
			}
			senderRatchet = key
			gotRatchet = true
		case 2: // counter
			if typ != protowire.VarintType {
				return senderRatchet, 0, 0, nil, nil, fmt.Errorf("%w: signal counter type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeVarint(body)
			if n < 0 {
				return senderRatchet, 0, 0, nil, nil, fmt.Errorf("%w: signal counter", signalerrors.ErrInvalidMessage)
			}
			body = body[n:]
			counter = uint32(val)
			gotCounter = true
		case 3: // previous_counter
			if typ != protowire.VarintType {
				return senderRatchet, 0, 0, nil, nil, fmt.Errorf("%w: signal previous counter type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeVarint(body)
			if n < 0 {
				return senderRatchet, 0, 0, nil, nil, fmt.Errorf("%w: signal previous counter", signalerrors.ErrInvalidMessage)
			}
			body = body[n:]
			previousCounter = uint32(val)
		case 4: // ciphertext
			if typ != protowire.BytesType {
				return senderRatchet, 0, 0, nil, nil, fmt.Errorf("%w: signal ciphertext type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeBytes(body)
			if n < 0 {
				return senderRatchet, 0, 0, nil, nil, fmt.Errorf("%w: signal ciphertext", signalerrors.ErrInvalidMessage)
			}
			body = body[n:]
			ciphertext = append([]byte(nil), val...)
			gotCiphertext = true
		case 5: // pq_ratchet
			if typ != protowire.BytesType {
				return senderRatchet, 0, 0, nil, nil, fmt.Errorf("%w: signal pq ratchet type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeBytes(body)
			if n < 0 {
				return senderRatchet, 0, 0, nil, nil, fmt.Errorf("%w: signal pq ratchet", signalerrors.ErrInvalidMessage)
			}
			body = body[n:]
			pqRatchet = append([]byte(nil), val...)
		default:
			n := protowire.ConsumeFieldValue(num, typ, body)
			if n < 0 {
				return senderRatchet, 0, 0, nil, nil, fmt.Errorf("%w: signal message field", signalerrors.ErrInvalidMessage)
			}
			body = body[n:]
		}
	}

	if !gotRatchet || !gotCounter || !gotCiphertext {
		return senderRatchet, 0, 0, nil, nil, fmt.Errorf("%w: signal message missing fields", signalerrors.ErrInvalidMessage)
	}

	return senderRatchet, counter, previousCounter, ciphertext, pqRatchet, nil
}
