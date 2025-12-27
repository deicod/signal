package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
)

// ErrInvalidPublicKey is returned when a provided Curve25519 public key is
// invalid or low-order.
var ErrInvalidPublicKey = errors.New("curve25519: invalid public key")

var validationScalar = [32]byte{1}

// KeyPair holds a Curve25519 key pair.
type KeyPair struct {
	PublicKey  [32]byte
	PrivateKey [32]byte
}

// GenerateKeyPair creates a new Curve25519 key pair using crypto/rand.
func GenerateKeyPair() (*KeyPair, error) {
	var priv [32]byte
	if _, err := io.ReadFull(rand.Reader, priv[:]); err != nil {
		return nil, fmt.Errorf("generate private key: %w", err)
	}
	pub, err := scalarBaseMult(priv)
	if err != nil {
		return nil, fmt.Errorf("derive public key: %w", err)
	}
	return &KeyPair{
		PublicKey:  pub,
		PrivateKey: priv,
	}, nil
}

// DH performs a Curve25519 Diffie-Hellman and rejects low-order public keys
// by ensuring the derived shared secret is not all zeros.
func DH(privateKey, publicKey [32]byte) ([32]byte, error) {
	var zero [32]byte

	shared, err := curve25519.X25519(privateKey[:], publicKey[:])
	if err != nil {
		return zero, errors.Join(ErrInvalidPublicKey, err)
	}

	var out [32]byte
	copy(out[:], shared)

	if subtle.ConstantTimeCompare(out[:], zero[:]) == 1 {
		return zero, ErrInvalidPublicKey
	}

	return out, nil
}

// ValidatePublicKey rejects low-order Curve25519 public keys.
func ValidatePublicKey(publicKey [32]byte) error {
	if !IsValidPublicKey(publicKey) {
		return ErrInvalidPublicKey
	}
	return nil
}

// IsValidPublicKey returns true if the Curve25519 public key is not low-order.
func IsValidPublicKey(publicKey [32]byte) bool {
	shared, err := curve25519.X25519(validationScalar[:], publicKey[:])
	if err != nil {
		return false
	}
	var zero [32]byte
	return subtle.ConstantTimeCompare(shared, zero[:]) != 1
}

func scalarBaseMult(privateKey [32]byte) ([32]byte, error) {
	var pub [32]byte
	out, err := curve25519.X25519(privateKey[:], curve25519.Basepoint[:])
	if err != nil {
		return pub, err
	}
	copy(pub[:], out)
	return pub, nil
}
