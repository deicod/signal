package x3dh

import (
	"encoding/binary"
	"fmt"

	"github.com/deicod/signal/keys"
)

const messageSerializeVersion byte = 2

// Serialize encodes the X3DH initial message into a stable byte format.
//
// Format (big-endian):
//
//	version(1)
//	identity_len(2) || identity_bytes(identity_len)
//	ephemeral_key(32)
//	has_pre_key(1) || pre_key_id(4)
//	signed_pre_key_id(4)
//	has_kyber(1) || kyber_pre_key_id(4) || kyber_ct_len(4) || kyber_ct(kyber_ct_len)
//	ciphertext_len(4) || ciphertext(ciphertext_len)
func (m *Message) Serialize() ([]byte, error) {
	if m == nil {
		return nil, fmt.Errorf("x3dh message: nil")
	}

	identityBytes, err := m.IdentityKey.Serialize()
	if err != nil {
		return nil, fmt.Errorf("x3dh message: serialize identity: %w", err)
	}
	if len(identityBytes) > int(^uint16(0)) {
		return nil, fmt.Errorf("x3dh message: identity too large")
	}

	hasPreKey := byte(0)
	if m.PreKeyID != nil {
		hasPreKey = 1
	}

	hasKyber := byte(0)
	if m.KyberPreKeyID != nil || len(m.KyberCiphertext) > 0 {
		if m.KyberPreKeyID == nil || len(m.KyberCiphertext) == 0 {
			return nil, fmt.Errorf("x3dh message: kyber id/ciphertext mismatch")
		}
		hasKyber = 1
	}

	kyberLen := 1
	if hasKyber == 1 {
		kyberLen += 4 + 4 + len(m.KyberCiphertext)
	}

	out := make([]byte, 1+2+len(identityBytes)+32+1+4+4+kyberLen+4+len(m.Ciphertext))
	pos := 0
	out[pos] = messageSerializeVersion
	pos++

	binary.BigEndian.PutUint16(out[pos:pos+2], uint16(len(identityBytes)))
	pos += 2
	copy(out[pos:pos+len(identityBytes)], identityBytes)
	pos += len(identityBytes)

	copy(out[pos:pos+32], m.EphemeralKey[:])
	pos += 32

	out[pos] = hasPreKey
	pos++
	if hasPreKey == 1 {
		binary.BigEndian.PutUint32(out[pos:pos+4], *m.PreKeyID)
	}
	pos += 4

	binary.BigEndian.PutUint32(out[pos:pos+4], m.SignedPreKeyID)
	pos += 4

	out[pos] = hasKyber
	pos++
	if hasKyber == 1 {
		binary.BigEndian.PutUint32(out[pos:pos+4], *m.KyberPreKeyID)
		pos += 4
		binary.BigEndian.PutUint32(out[pos:pos+4], uint32(len(m.KyberCiphertext)))
		pos += 4
		copy(out[pos:pos+len(m.KyberCiphertext)], m.KyberCiphertext)
		pos += len(m.KyberCiphertext)
	}

	binary.BigEndian.PutUint32(out[pos:pos+4], uint32(len(m.Ciphertext)))
	pos += 4
	copy(out[pos:], m.Ciphertext)

	return out, nil
}

// DeserializeMessage decodes an X3DH initial message created by (*Message).Serialize.
func DeserializeMessage(data []byte) (*Message, error) {
	pos := 0
	if len(data) < 1 {
		return nil, fmt.Errorf("x3dh message: too short")
	}
	version := data[pos]
	pos++
	if version == 1 {
		const minLen = 1 + 2 + 32 + 1 + 4 + 4 + 4
		if len(data) < minLen {
			return nil, fmt.Errorf("x3dh message: too short")
		}

		identityLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
		pos += 2
		if identityLen <= 0 || pos+identityLen > len(data) {
			return nil, fmt.Errorf("x3dh message: invalid identity length")
		}
		identity, err := keys.DeserializeIdentityKey(data[pos : pos+identityLen])
		if err != nil {
			return nil, fmt.Errorf("x3dh message: %w", err)
		}
		pos += identityLen

		if pos+32+1+4+4+4 > len(data) {
			return nil, fmt.Errorf("x3dh message: truncated")
		}
		var eph [32]byte
		copy(eph[:], data[pos:pos+32])
		pos += 32

		hasPreKey := data[pos]
		pos++
		var preKeyID *uint32
		if hasPreKey == 1 {
			id := binary.BigEndian.Uint32(data[pos : pos+4])
			preKeyID = &id
		} else if hasPreKey != 0 {
			return nil, fmt.Errorf("x3dh message: invalid pre-key flag")
		}
		pos += 4

		signedPreKeyID := binary.BigEndian.Uint32(data[pos : pos+4])
		pos += 4

		ctLen := int(binary.BigEndian.Uint32(data[pos : pos+4]))
		pos += 4
		if ctLen < 0 || pos+ctLen != len(data) {
			return nil, fmt.Errorf("x3dh message: invalid ciphertext length")
		}
		ct := append([]byte(nil), data[pos:]...)

		return &Message{
			IdentityKey:    *identity,
			EphemeralKey:   eph,
			PreKeyID:       preKeyID,
			SignedPreKeyID: signedPreKeyID,
			Ciphertext:     ct,
		}, nil
	}
	if version != messageSerializeVersion {
		return nil, fmt.Errorf("x3dh message: unsupported version %d", version)
	}

	const minLen = 1 + 2 + 32 + 1 + 4 + 4 + 1 + 4
	if len(data) < minLen {
		return nil, fmt.Errorf("x3dh message: too short")
	}

	identityLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	if identityLen <= 0 || pos+identityLen > len(data) {
		return nil, fmt.Errorf("x3dh message: invalid identity length")
	}
	identity, err := keys.DeserializeIdentityKey(data[pos : pos+identityLen])
	if err != nil {
		return nil, fmt.Errorf("x3dh message: %w", err)
	}
	pos += identityLen

	if pos+32+1+4+4+1+4 > len(data) {
		return nil, fmt.Errorf("x3dh message: truncated")
	}
	var eph [32]byte
	copy(eph[:], data[pos:pos+32])
	pos += 32

	hasPreKey := data[pos]
	pos++
	var preKeyID *uint32
	if hasPreKey == 1 {
		id := binary.BigEndian.Uint32(data[pos : pos+4])
		preKeyID = &id
	} else if hasPreKey != 0 {
		return nil, fmt.Errorf("x3dh message: invalid pre-key flag")
	}
	pos += 4

	signedPreKeyID := binary.BigEndian.Uint32(data[pos : pos+4])
	pos += 4

	hasKyber := data[pos]
	pos++
	var kyberPreKeyID *uint32
	var kyberCiphertext []byte
	if hasKyber == 1 {
		id := binary.BigEndian.Uint32(data[pos : pos+4])
		pos += 4
		kyberLen := int(binary.BigEndian.Uint32(data[pos : pos+4]))
		pos += 4
		if kyberLen <= 0 || pos+kyberLen > len(data) {
			return nil, fmt.Errorf("x3dh message: invalid kyber ciphertext length")
		}
		kyberCiphertext = append([]byte(nil), data[pos:pos+kyberLen]...)
		pos += kyberLen
		kyberPreKeyID = &id
	} else if hasKyber != 0 {
		return nil, fmt.Errorf("x3dh message: invalid kyber flag")
	}

	ctLen := int(binary.BigEndian.Uint32(data[pos : pos+4]))
	pos += 4
	if ctLen < 0 || pos+ctLen != len(data) {
		return nil, fmt.Errorf("x3dh message: invalid ciphertext length")
	}
	ct := append([]byte(nil), data[pos:]...)

	return &Message{
		IdentityKey:     *identity,
		EphemeralKey:    eph,
		PreKeyID:        preKeyID,
		SignedPreKeyID:  signedPreKeyID,
		KyberPreKeyID:   kyberPreKeyID,
		KyberCiphertext: kyberCiphertext,
		Ciphertext:      ct,
	}, nil
}
