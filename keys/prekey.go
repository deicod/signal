package keys

import (
	"fmt"
	"time"

	signalcrypto "github.com/deicod/signal/crypto"
)

// PreKey represents a one-time pre-key.
type PreKey struct {
	ID        uint32
	KeyPair   *signalcrypto.KeyPair
	Timestamp time.Time
}

// SignedPreKey represents a long-lived signed pre-key.
type SignedPreKey struct {
	ID        uint32
	KeyPair   *signalcrypto.KeyPair
	Signature []byte
	Timestamp time.Time
}

// GeneratePreKey creates a single pre-key with the given ID.
func GeneratePreKey(id uint32) (*PreKey, error) {
	kp, err := signalcrypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate pre-key: %w", err)
	}
	return &PreKey{
		ID:        id,
		KeyPair:   kp,
		Timestamp: time.Now().UTC(),
	}, nil
}

// GeneratePreKeys creates a sequence of pre-keys starting at startID.
func GeneratePreKeys(startID uint32, count int) ([]*PreKey, error) {
	if count < 0 {
		return nil, fmt.Errorf("count must be non-negative")
	}
	keys := make([]*PreKey, 0, count)
	for i := 0; i < count; i++ {
		pk, err := GeneratePreKey(startID + uint32(i))
		if err != nil {
			return nil, err
		}
		keys = append(keys, pk)
	}
	return keys, nil
}

// GenerateSignedPreKey creates a signed pre-key using the identity key for signature.
func GenerateSignedPreKey(identityKey *IdentityKeyPair, id uint32) (*SignedPreKey, error) {
	if identityKey == nil {
		return nil, fmt.Errorf("identity key required")
	}
	kp, err := signalcrypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate signed pre-key: %w", err)
	}
	sig, err := identityKey.Sign(kp.PublicKey[:])
	if err != nil {
		return nil, fmt.Errorf("sign pre-key: %w", err)
	}
	return &SignedPreKey{
		ID:        id,
		KeyPair:   kp,
		Signature: sig,
		Timestamp: time.Now().UTC(),
	}, nil
}

// VerifySignedPreKey checks that the signature matches the identity key.
func (spk *SignedPreKey) VerifySignedPreKey(identity *IdentityKey) bool {
	if spk == nil || identity == nil {
		return false
	}
	return identity.Verify(spk.KeyPair.PublicKey[:], spk.Signature)
}
