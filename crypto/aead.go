package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// AEAD defines authenticated encryption with associated data using combined
// nonce+ciphertext encoding. Encrypt returns nonce||ciphertext||tag; Decrypt
// expects the same format and uses NonceSize to split.
type AEAD interface {
	Encrypt(key, plaintext, ad []byte) ([]byte, error)
	Decrypt(key, ciphertext, ad []byte) ([]byte, error)
	KeySize() int
	NonceSize() int
}

// ErrInvalidKey is returned when the key length is incorrect.
var ErrInvalidKey = errors.New("aead: invalid key length")

// ErrCiphertextTooShort is returned when the ciphertext is shorter than the nonce/tag requirements.
var ErrCiphertextTooShort = errors.New("aead: ciphertext too short")

// AESGCM implements AEAD using AES-256-GCM.
type AESGCM struct {
	rand io.Reader
}

// NewAESGCM returns an AES-256-GCM AEAD; if r is nil crypto/rand.Reader is used.
func NewAESGCM(r io.Reader) *AESGCM {
	if r == nil {
		r = rand.Reader
	}
	return &AESGCM{rand: r}
}

// KeySize returns the expected key length in bytes.
func (a *AESGCM) KeySize() int { return 32 }

// NonceSize returns the nonce length in bytes.
func (a *AESGCM) NonceSize() int { return 12 }

// Encrypt generates a random nonce, encrypts plaintext, and returns nonce||ciphertext||tag.
func (a *AESGCM) Encrypt(key, plaintext, ad []byte) ([]byte, error) {
	if len(key) != a.KeySize() {
		return nil, ErrInvalidKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	nonce := make([]byte, a.NonceSize())
	if _, err := io.ReadFull(a.rand, nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, ad)
	return append(nonce, ciphertext...), nil
}

// Decrypt splits nonce||ciphertext||tag and decrypts.
func (a *AESGCM) Decrypt(key, ciphertext, ad []byte) ([]byte, error) {
	if len(key) != a.KeySize() {
		return nil, ErrInvalidKey
	}
	if len(ciphertext) < a.NonceSize() {
		return nil, ErrCiphertextTooShort
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	nonce := ciphertext[:a.NonceSize()]
	body := ciphertext[a.NonceSize():]
	plain, err := gcm.Open(nil, nonce, body, ad)
	if err != nil {
		return nil, err
	}
	return plain, nil
}

// AESGCMEncrypt is a convenience wrapper returning ciphertext and nonce separately.
func AESGCMEncrypt(key, plaintext, associatedData []byte) (ciphertext, nonce []byte, err error) {
	a := NewAESGCM(nil)
	c, err := a.Encrypt(key, plaintext, associatedData)
	if err != nil {
		return nil, nil, err
	}
	nonceSize := a.NonceSize()
	return bytes.Clone(c[nonceSize:]), bytes.Clone(c[:nonceSize]), nil
}

// AESGCMDecrypt decrypts using AES-256-GCM with the provided nonce.
func AESGCMDecrypt(key, ciphertext, nonce, associatedData []byte) ([]byte, error) {
	if len(nonce) != 12 {
		return nil, ErrCiphertextTooShort
	}
	a := NewAESGCM(nil)
	combined := append(bytes.Clone(nonce), ciphertext...)
	return a.Decrypt(key, combined, associatedData)
}

// ChaChaAEAD implements AEAD using ChaCha20-Poly1305.
type ChaChaAEAD struct {
	rand io.Reader
}

// NewChaChaAEAD returns a ChaCha20-Poly1305 AEAD; if r is nil crypto/rand.Reader is used.
func NewChaChaAEAD(r io.Reader) *ChaChaAEAD {
	if r == nil {
		r = rand.Reader
	}
	return &ChaChaAEAD{rand: r}
}

// KeySize returns the expected key length in bytes.
func (c *ChaChaAEAD) KeySize() int { return chacha20poly1305.KeySize }

// NonceSize returns the nonce length in bytes.
func (c *ChaChaAEAD) NonceSize() int { return chacha20poly1305.NonceSize }

// Encrypt generates a random nonce, encrypts plaintext, and returns nonce||ciphertext||tag.
func (c *ChaChaAEAD) Encrypt(key, plaintext, ad []byte) ([]byte, error) {
	if len(key) != c.KeySize() {
		return nil, ErrInvalidKey
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("chacha20poly1305: %w", err)
	}
	nonce := make([]byte, c.NonceSize())
	if _, err := io.ReadFull(c.rand, nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, ad)
	return append(nonce, ciphertext...), nil
}

// Decrypt splits nonce||ciphertext||tag and decrypts.
func (c *ChaChaAEAD) Decrypt(key, ciphertext, ad []byte) ([]byte, error) {
	if len(key) != c.KeySize() {
		return nil, ErrInvalidKey
	}
	if len(ciphertext) < c.NonceSize() {
		return nil, ErrCiphertextTooShort
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("chacha20poly1305: %w", err)
	}
	nonce := ciphertext[:c.NonceSize()]
	body := ciphertext[c.NonceSize():]
	plain, err := aead.Open(nil, nonce, body, ad)
	if err != nil {
		return nil, err
	}
	return plain, nil
}

// ChaChaEncrypt is a convenience wrapper returning ciphertext and nonce separately.
func ChaChaEncrypt(key, plaintext, associatedData []byte) (ciphertext, nonce []byte, err error) {
	c := NewChaChaAEAD(nil)
	out, err := c.Encrypt(key, plaintext, associatedData)
	if err != nil {
		return nil, nil, err
	}
	nonceSize := c.NonceSize()
	return bytes.Clone(out[nonceSize:]), bytes.Clone(out[:nonceSize]), nil
}

// ChaChaDecrypt decrypts using ChaCha20-Poly1305 with the provided nonce.
func ChaChaDecrypt(key, ciphertext, nonce, associatedData []byte) ([]byte, error) {
	if len(nonce) != chacha20poly1305.NonceSize {
		return nil, ErrCiphertextTooShort
	}
	c := NewChaChaAEAD(nil)
	combined := append(bytes.Clone(nonce), ciphertext...)
	return c.Decrypt(key, combined, associatedData)
}
