package keys

import (
	"fmt"
	"time"

	signalcrypto "github.com/deicod/signal/crypto"
)

// KyberKeyPair holds a serialized Kyber key pair (type-prefixed bytes).
type KyberKeyPair struct {
	PublicKey  []byte
	PrivateKey []byte
}

// KyberPreKey represents a long-lived signed Kyber pre-key.
type KyberPreKey struct {
	ID        uint32
	KeyPair   *KyberKeyPair
	Signature []byte
	Timestamp time.Time
}

// GenerateKyberPreKey creates a signed Kyber pre-key using the identity key for signature.
func GenerateKyberPreKey(identityKey *IdentityKeyPair, id uint32) (*KyberPreKey, error) {
	if identityKey == nil {
		return nil, fmt.Errorf("identity key required")
	}
	kp, err := signalcrypto.GenerateKyber1024KeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate kyber pre-key: %w", err)
	}
	sig, err := identityKey.Sign(kp.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("sign kyber pre-key: %w", err)
	}
	return &KyberPreKey{
		ID:        id,
		KeyPair:   &KyberKeyPair{PublicKey: append([]byte(nil), kp.PublicKey...), PrivateKey: append([]byte(nil), kp.PrivateKey...)},
		Signature: sig,
		Timestamp: time.Now().UTC(),
	}, nil
}

// VerifyKyberPreKey checks that the signature matches the identity key.
func (kp *KyberPreKey) VerifyKyberPreKey(identity *IdentityKey) bool {
	if kp == nil || identity == nil || kp.KeyPair == nil {
		return false
	}
	return identity.Verify(kp.KeyPair.PublicKey, kp.Signature)
}
