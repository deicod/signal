package keys

import (
	"encoding/binary"
	"errors"
	"fmt"

	signalcrypto "github.com/deicod/signal/crypto"
)

const serializeVersion byte = 1

// Serialize encodes the identity key with a version prefix.
func (k *IdentityKey) Serialize() ([]byte, error) {
	if k == nil {
		return nil, errors.New("identity key is nil")
	}
	out := make([]byte, 1+32+32)
	out[0] = serializeVersion
	copy(out[1:33], k.PublicKey[:])
	copy(out[33:], k.SigningPublic[:])
	return out, nil
}

// DeserializeIdentityKey decodes an identity key.
func DeserializeIdentityKey(data []byte) (*IdentityKey, error) {
	if len(data) != 1+32+32 {
		return nil, fmt.Errorf("identity key: invalid length %d", len(data))
	}
	if data[0] != serializeVersion {
		return nil, fmt.Errorf("identity key: unsupported version %d", data[0])
	}
	var k IdentityKey
	copy(k.PublicKey[:], data[1:33])
	copy(k.SigningPublic[:], data[33:])
	return &k, nil
}

// Serialize encodes a pre-key (public only) with ID and version.
func (p *PreKey) Serialize() ([]byte, error) {
	if p == nil || p.KeyPair == nil {
		return nil, errors.New("pre-key is nil")
	}
	out := make([]byte, 1+4+32)
	out[0] = serializeVersion
	binary.BigEndian.PutUint32(out[1:5], p.ID)
	copy(out[5:], p.KeyPair.PublicKey[:])
	return out, nil
}

// DeserializePreKey decodes a pre-key (public only).
func DeserializePreKey(data []byte) (*PreKey, error) {
	if len(data) != 1+4+32 {
		return nil, fmt.Errorf("pre-key: invalid length %d", len(data))
	}
	if data[0] != serializeVersion {
		return nil, fmt.Errorf("pre-key: unsupported version %d", data[0])
	}
	id := binary.BigEndian.Uint32(data[1:5])
	var pub [32]byte
	copy(pub[:], data[5:])
	return &PreKey{
		ID: id,
		KeyPair: &signalcrypto.KeyPair{
			PublicKey: pub,
		},
	}, nil
}

// Serialize encodes a signed pre-key (public + signature).
func (spk *SignedPreKey) Serialize() ([]byte, error) {
	if spk == nil || spk.KeyPair == nil {
		return nil, errors.New("signed pre-key is nil")
	}
	if len(spk.Signature) == 0 {
		return nil, errors.New("signed pre-key missing signature")
	}
	sigLen := len(spk.Signature)
	out := make([]byte, 1+4+2+32+sigLen)
	out[0] = serializeVersion
	binary.BigEndian.PutUint32(out[1:5], spk.ID)
	binary.BigEndian.PutUint16(out[5:7], uint16(sigLen))
	copy(out[7:39], spk.KeyPair.PublicKey[:])
	copy(out[39:], spk.Signature)
	return out, nil
}

// DeserializeSignedPreKey decodes a signed pre-key.
func DeserializeSignedPreKey(data []byte) (*SignedPreKey, error) {
	if len(data) < 1+4+2+32 {
		return nil, fmt.Errorf("signed pre-key: invalid length %d", len(data))
	}
	if data[0] != serializeVersion {
		return nil, fmt.Errorf("signed pre-key: unsupported version %d", data[0])
	}
	sigLen := int(binary.BigEndian.Uint16(data[5:7]))
	expected := 1 + 4 + 2 + 32 + sigLen
	if len(data) != expected {
		return nil, fmt.Errorf("signed pre-key: signature length mismatch")
	}
	id := binary.BigEndian.Uint32(data[1:5])
	var pub [32]byte
	copy(pub[:], data[7:39])
	sig := make([]byte, sigLen)
	copy(sig, data[39:])
	return &SignedPreKey{
		ID: id,
		KeyPair: &signalcrypto.KeyPair{
			PublicKey: pub,
		},
		Signature: sig,
	}, nil
}

// Serialize encodes the bundle without private keys.
func (b *PreKeyBundle) Serialize() ([]byte, error) {
	if b == nil {
		return nil, errors.New("bundle is nil")
	}
	identityBytes, err := b.IdentityKey.Serialize()
	if err != nil {
		return nil, err
	}
	hasPreKey := byte(0)
	preKeyLen := 0
	if b.PreKeyID != nil && b.PreKeyPublic != nil {
		hasPreKey = 1
		preKeyLen = 4 + 32
	}
	sigLen := len(b.SignedPreKeySignature)
	out := make([]byte, 1+4+4+1+preKeyLen+4+32+2+sigLen+len(identityBytes))
	pos := 0
	out[pos] = serializeVersion
	pos++
	binary.BigEndian.PutUint32(out[pos:pos+4], b.RegistrationID)
	pos += 4
	binary.BigEndian.PutUint32(out[pos:pos+4], b.DeviceID)
	pos += 4
	out[pos] = hasPreKey
	pos++
	if hasPreKey == 1 {
		binary.BigEndian.PutUint32(out[pos:pos+4], *b.PreKeyID)
		pos += 4
		copy(out[pos:pos+32], b.PreKeyPublic[:])
		pos += 32
	}
	binary.BigEndian.PutUint32(out[pos:pos+4], b.SignedPreKeyID)
	pos += 4
	copy(out[pos:pos+32], b.SignedPreKeyPublic[:])
	pos += 32
	binary.BigEndian.PutUint16(out[pos:pos+2], uint16(sigLen))
	pos += 2
	copy(out[pos:pos+sigLen], b.SignedPreKeySignature)
	pos += sigLen
	copy(out[pos:], identityBytes)
	return out, nil
}

// DeserializePreKeyBundle decodes a bundle.
func DeserializePreKeyBundle(data []byte) (*PreKeyBundle, error) {
	if len(data) < 1+4+4+1+4+32+4+32+2 {
		return nil, fmt.Errorf("bundle: invalid length %d", len(data))
	}
	pos := 0
	version := data[pos]
	pos++
	if version != serializeVersion {
		return nil, fmt.Errorf("bundle: unsupported version %d", version)
	}
	if pos+8 > len(data) {
		return nil, fmt.Errorf("bundle: truncated header")
	}
	reg := binary.BigEndian.Uint32(data[pos : pos+4])
	pos += 4
	device := binary.BigEndian.Uint32(data[pos : pos+4])
	pos += 4
	hasPreKey := data[pos]
	pos++

	var preKeyID *uint32
	var preKeyPub *[32]byte
	if hasPreKey == 1 {
		if pos+4+32 > len(data) {
			return nil, fmt.Errorf("bundle: truncated pre-key")
		}
		id := binary.BigEndian.Uint32(data[pos : pos+4])
		pos += 4
		var pub [32]byte
		copy(pub[:], data[pos:pos+32])
		pos += 32
		preKeyID = &id
		preKeyPub = &pub
	}
	if pos+4+32+2 > len(data) {
		return nil, fmt.Errorf("bundle: truncated signed pre-key")
	}
	signedID := binary.BigEndian.Uint32(data[pos : pos+4])
	pos += 4
	var signedPub [32]byte
	copy(signedPub[:], data[pos:pos+32])
	pos += 32
	sigLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	if pos+sigLen > len(data) {
		return nil, fmt.Errorf("bundle: truncated signature")
	}
	sig := make([]byte, sigLen)
	copy(sig, data[pos:pos+sigLen])
	pos += sigLen

	identity, err := DeserializeIdentityKey(data[pos:])
	if err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}

	return &PreKeyBundle{
		RegistrationID:        reg,
		DeviceID:              device,
		PreKeyID:              preKeyID,
		PreKeyPublic:          preKeyPub,
		SignedPreKeyID:        signedID,
		SignedPreKeyPublic:    signedPub,
		SignedPreKeySignature: sig,
		IdentityKey:           *identity,
	}, nil
}
