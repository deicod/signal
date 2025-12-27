package signal

import (
	"github.com/deicod/signal/keys"
	"github.com/deicod/signal/session"
	"github.com/deicod/signal/store"
)

// Address identifies a remote party (name/device).
type Address = store.Address

// ProtocolStore persists identity keys, pre-keys, and session state.
type ProtocolStore = store.ProtocolStore

// PreKeyBundle is the public bundle a recipient publishes for X3DH bootstrap.
type PreKeyBundle = keys.PreKeyBundle

// Cipher offers a byte-oriented Encrypt/Decrypt API for a 1:1 session with a remote Address.
//
// Cipher is a thin wrapper around session.WireCipher and targets libsignal wire compatibility.
type Cipher struct {
	inner *session.WireCipher
}

// NewCipher builds a Cipher bound to a ProtocolStore and remote Address.
func NewCipher(s ProtocolStore, addr Address) *Cipher {
	return &Cipher{inner: session.NewWireCipher(s, addr)}
}

// Encrypt uses the current session to encrypt plaintext. A session must already exist in the store.
func (c *Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	return c.inner.Encrypt(plaintext)
}

// Decrypt decrypts a ciphertext envelope using either an existing session or a pre-key bootstrap message.
func (c *Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
	return c.inner.Decrypt(ciphertext)
}

// EncryptWithPreKeyBundle bootstraps a new session using the recipient's pre-key bundle and returns
// a ciphertext envelope containing the X3DH initial message plus the first Double Ratchet message.
func (c *Cipher) EncryptWithPreKeyBundle(bundle *PreKeyBundle, plaintext []byte) ([]byte, error) {
	return c.inner.EncryptWithPreKeyBundle(bundle, plaintext)
}
