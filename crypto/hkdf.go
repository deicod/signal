package crypto

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const hkdfMaxLength = 255 * sha256.Size

// ErrHKDFLength is returned when HKDF output length is invalid.
var ErrHKDFLength = errors.New("hkdf: invalid length")

// HKDFExtract performs HKDF-Extract with SHA-256.
func HKDFExtract(salt, inputKeyMaterial []byte) []byte {
	return hkdf.Extract(sha256.New, inputKeyMaterial, salt)
}

// HKDFExpand performs HKDF-Expand with SHA-256.
func HKDFExpand(prk, info []byte, length int) ([]byte, error) {
	if length < 0 || length > hkdfMaxLength {
		return nil, fmt.Errorf("%w: length must be between 0 and %d", ErrHKDFLength, hkdfMaxLength)
	}

	okm := make([]byte, length)
	reader := hkdf.Expand(sha256.New, prk, info)
	if _, err := io.ReadFull(reader, okm); err != nil {
		return nil, fmt.Errorf("hkdf expand: %w", err)
	}

	return okm, nil
}

// HKDF performs HKDF-Extract then HKDF-Expand with SHA-256.
func HKDF(inputKeyMaterial, salt, info []byte, length int) ([]byte, error) {
	prk := HKDFExtract(salt, inputKeyMaterial)
	return HKDFExpand(prk, info, length)
}
