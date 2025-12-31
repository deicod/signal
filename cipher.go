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
// It maintains the session state (ratchets) and persists changes to the ProtocolStore.
//
// Cipher is a thin wrapper around session.WireCipher and targets libsignal wire compatibility.
// For legacy envelope format support, see session.Cipher.
type Cipher struct {
	inner *session.WireCipher
}

// NewCipher builds a Cipher bound to a ProtocolStore and remote Address.
// The store must be initialized and capable of persisting session records.
func NewCipher(s ProtocolStore, addr Address) *Cipher {
	return &Cipher{inner: session.NewWireCipher(s, addr)}
}

// Encrypt encrypts plaintext using the current session.
//
// It returns an error if no session exists for the remote address. Use EncryptWithPreKeyBundle
// to establish a new session. This method advances the ratchet and persists the updated session state.
func (c *Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	return c.inner.Encrypt(plaintext)
}

// Decrypt decrypts a ciphertext message using an existing session or a pre-key bootstrap message.
//
// It handles both standard SignalMessages and PreKeySignalMessages (which establish new sessions).
// On success, it returns the plaintext and persists any session state changes (e.g., ratchet steps).
func (c *Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
	return c.inner.Decrypt(ciphertext)
}

// EncryptWithPreKeyBundle bootstraps a new session using the recipient's pre-key bundle.
//
// It performs an X3DH key exchange and returns a PreKeySignalMessage containing the initial
// ciphertext. This should be used for the very first message sent to a recipient.
func (c *Cipher) EncryptWithPreKeyBundle(bundle *PreKeyBundle, plaintext []byte) ([]byte, error) {
	return c.inner.EncryptWithPreKeyBundle(bundle, plaintext)
}
