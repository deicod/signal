package keys

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	signalcrypto "github.com/deicod/signal/crypto"
)

// IdentityKey wraps the Curve25519 public key used for DH along with the
// corresponding XEdDSA signing public key.
type IdentityKey struct {
	PublicKey     [32]byte // Curve25519 public key
	SigningPublic [32]byte // XEdDSA signing public key
}

// IdentityKeyPair holds the curve25519 private key and associated public keys.
type IdentityKeyPair struct {
	PublicKey  IdentityKey
	PrivateKey [32]byte
}

// GenerateIdentityKeyPair creates a new identity key pair backed by a
// Curve25519 key and a matching XEdDSA signing key derived from the same secret.
func GenerateIdentityKeyPair() (*IdentityKeyPair, error) {
	kp, err := signalcrypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate curve25519 key: %w", err)
	}

	var signingPub [32]byte
	signingPub, err = signalcrypto.XEdDSASigningPublicKey(kp.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("derive xeddsa public key: %w", err)
	}

	return &IdentityKeyPair{
		PublicKey: IdentityKey{
			PublicKey:     kp.PublicKey,
			SigningPublic: signingPub,
		},
		PrivateKey: kp.PrivateKey,
	}, nil
}

// Sign produces an XEdDSA signature over the message using the identity key.
func (k *IdentityKeyPair) Sign(message []byte) ([]byte, error) {
	return signalcrypto.XEdDSASign(k.PrivateKey, message)
}

// Verify checks an XEdDSA signature against the identity's public key.
func (k *IdentityKey) Verify(message, signature []byte) bool {
	return signalcrypto.XEdDSAVerify(k.PublicKey, signature, message)
}

// Fingerprint returns a base64url (no padding) encoded SHA-256 digest of the
// curve25519 public key, suitable for display or comparison.
func (k *IdentityKey) Fingerprint() string {
	sum := sha256.Sum256(k.PublicKey[:])
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// FromBytes creates an IdentityKey from raw curve25519 and XEdDSA public keys.
func FromBytes(curvePub, signingPub []byte) (IdentityKey, error) {
	var ik IdentityKey
	if len(curvePub) != 32 || len(signingPub) != 32 {
		return ik, errors.New("identity: public keys must be 32 bytes")
	}
	copy(ik.PublicKey[:], curvePub)
	copy(ik.SigningPublic[:], signingPub)
	if err := signalcrypto.ValidatePublicKey(ik.PublicKey); err != nil {
		return ik, fmt.Errorf("identity: invalid public key")
	}
	return ik, nil
}
