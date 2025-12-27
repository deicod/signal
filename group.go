package signal

import (
	"github.com/deicod/signal/senderkeys"
	"github.com/deicod/signal/store"
)

// SenderKeyName identifies a Sender Key state for a (group + sender) tuple.
type SenderKeyName = store.SenderKeyName

// GroupSessionBuilder creates and processes Sender Key distribution messages for a group.
type GroupSessionBuilder struct {
	inner *senderkeys.Builder
}

// NewGroupSessionBuilder constructs a GroupSessionBuilder for the given store and sender key name.
func NewGroupSessionBuilder(s ProtocolStore, name SenderKeyName) *GroupSessionBuilder {
	return &GroupSessionBuilder{inner: senderkeys.NewBuilder(s, name)}
}

// Create returns a distribution message for the current sender key state, creating one if absent.
func (b *GroupSessionBuilder) Create() ([]byte, error) {
	return b.inner.Create()
}

// Rotate generates a new sender key state and returns its distribution message.
func (b *GroupSessionBuilder) Rotate() ([]byte, error) {
	return b.inner.Rotate()
}

// Process updates the sender key record using a received distribution message.
func (b *GroupSessionBuilder) Process(distribution []byte) error {
	return b.inner.Process(distribution)
}

// GroupCipher provides Encrypt/Decrypt for Sender Key group messages for a (group, sender) tuple.
type GroupCipher struct {
	inner *senderkeys.Cipher
}

// NewGroupCipher constructs a GroupCipher for the given store and sender key name.
func NewGroupCipher(s ProtocolStore, name SenderKeyName) *GroupCipher {
	return &GroupCipher{inner: senderkeys.NewCipher(s, name)}
}

// Encrypt encrypts plaintext using the current sender key state.
func (c *GroupCipher) Encrypt(plaintext []byte) ([]byte, error) {
	return c.inner.Encrypt(plaintext)
}

// Decrypt decrypts a sender key group message, updating the sender key state on success.
func (c *GroupCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	return c.inner.Decrypt(ciphertext)
}
