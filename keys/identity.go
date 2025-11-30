package keys

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	signalcrypto "github.com/deicod/signal/crypto"
)

// IdentityKey wraps the curve25519 public key used for DH along with the
// corresponding Ed25519 public key for signatures.
type IdentityKey struct {
	PublicKey     [32]byte // Curve25519 public key
	SigningPublic [32]byte // Ed25519 public key
}

// IdentityKeyPair holds the curve25519 private key and associated public keys.
type IdentityKeyPair struct {
	PublicKey  IdentityKey
	PrivateKey [32]byte
}

// GenerateIdentityKeyPair creates a new identity key pair backed by a
// curve25519 key and a matching Ed25519 signing key derived from the same seed.
func GenerateIdentityKeyPair() (*IdentityKeyPair, error) {
	kp, err := signalcrypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate curve25519 key: %w", err)
	}

	edPriv := ed25519.NewKeyFromSeed(kp.PrivateKey[:])
	edPub := edPriv.Public().(ed25519.PublicKey)

	var signingPub [32]byte
	copy(signingPub[:], edPub)

	return &IdentityKeyPair{
		PublicKey: IdentityKey{
			PublicKey:     kp.PublicKey,
			SigningPublic: signingPub,
		},
		PrivateKey: kp.PrivateKey,
	}, nil
}

// Sign produces an Ed25519 signature over the message using the identity key.
func (k *IdentityKeyPair) Sign(message []byte) ([]byte, error) {
	edPriv := ed25519.NewKeyFromSeed(k.PrivateKey[:])
	sig := ed25519.Sign(edPriv, message)
	return sig, nil
}

// Verify checks an Ed25519 signature against the identity's signing public key.
func (k *IdentityKey) Verify(message, signature []byte) bool {
	pub := ed25519.PublicKey(k.SigningPublic[:])
	return ed25519.Verify(pub, message, signature)
}

// Fingerprint returns a base64url (no padding) encoded SHA-256 digest of the
// curve25519 public key, suitable for display or comparison.
func (k *IdentityKey) Fingerprint() string {
	sum := sha256.Sum256(k.PublicKey[:])
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// FromBytes creates an IdentityKey from raw curve25519 and Ed25519 public keys.
func FromBytes(curvePub, signingPub []byte) (IdentityKey, error) {
	var ik IdentityKey
	if len(curvePub) != 32 || len(signingPub) != 32 {
		return ik, errors.New("identity: public keys must be 32 bytes")
	}
	copy(ik.PublicKey[:], curvePub)
	copy(ik.SigningPublic[:], signingPub)
	return ik, nil
}
