package signal

import "github.com/deicod/signal/session"

// EnvelopeCipher offers Encrypt/Decrypt using the legacy internal envelope format.
//
// EnvelopeCipher is a thin wrapper around session.Cipher.
type EnvelopeCipher struct {
	inner *session.Cipher
}

// NewEnvelopeCipher builds an EnvelopeCipher bound to a ProtocolStore and remote Address.
func NewEnvelopeCipher(s ProtocolStore, addr Address) *EnvelopeCipher {
	return &EnvelopeCipher{inner: session.NewCipher(s, addr)}
}

// Encrypt uses the current session to encrypt plaintext. A session must already exist in the store.
func (c *EnvelopeCipher) Encrypt(plaintext []byte) ([]byte, error) {
	return c.inner.Encrypt(plaintext)
}

// Decrypt decrypts a ciphertext envelope using either an existing session or a pre-key bootstrap message.
func (c *EnvelopeCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	return c.inner.Decrypt(ciphertext)
}

// EncryptWithPreKeyBundle bootstraps a new session using the recipient's pre-key bundle and returns
// a ciphertext envelope containing the X3DH initial message plus the first Double Ratchet message.
func (c *EnvelopeCipher) EncryptWithPreKeyBundle(bundle *PreKeyBundle, plaintext []byte) ([]byte, error) {
	return c.inner.EncryptWithPreKeyBundle(bundle, plaintext)
}
