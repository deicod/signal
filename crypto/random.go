package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// randReader is the source of randomness; override in tests.
var randReader = rand.Reader

// ErrInvalidLength is returned when a negative or oversized length is requested.
var ErrInvalidLength = errors.New("random: invalid length")

// RandomBytes returns securely generated random bytes of the requested length.
func RandomBytes(length int) ([]byte, error) {
	if length < 0 {
		return nil, ErrInvalidLength
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(randReader, buf); err != nil {
		return nil, fmt.Errorf("random bytes: %w", err)
	}
	return buf, nil
}

// RandomScalar returns a clamped Curve25519 private scalar.
func RandomScalar() ([32]byte, error) {
	var scalar [32]byte
	b, err := RandomBytes(len(scalar))
	if err != nil {
		return scalar, err
	}
	copy(scalar[:], b)
	clampCurve25519Scalar(&scalar)
	return scalar, nil
}

func clampCurve25519Scalar(s *[32]byte) {
	s[0] &= 248
	s[31] &= 127
	s[31] |= 64
}
