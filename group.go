package signal

import (
	"github.com/deicod/signal/senderkeys"
	"github.com/deicod/signal/store"
)

// SenderKeyName identifies a Sender Key state for a (group + sender) tuple.
type SenderKeyName = store.SenderKeyName

// GroupSessionBuilder manages the creation and processing of Sender Key distribution messages.
// These messages are used to establish the encryption keys for a group session.
type GroupSessionBuilder struct {
	inner *senderkeys.Builder
}

// NewGroupSessionBuilder constructs a GroupSessionBuilder for the given store and sender key name.
// The name identifies the (group, sender) tuple for which keys are being managed.
func NewGroupSessionBuilder(s ProtocolStore, name SenderKeyName) *GroupSessionBuilder {
	return &GroupSessionBuilder{inner: senderkeys.NewBuilder(s, name)}
}

// Create returns a SenderKeyDistributionMessage for the current sender key state.
// If no state exists, a new one is created. This message should be sent to other group members
// (typically over 1:1 sessions) so they can decrypt messages from this sender.
func (b *GroupSessionBuilder) Create() ([]byte, error) {
	return b.inner.Create()
}

// Rotate generates a new sender key state and returns its distribution message.
// This should be called when group membership changes (e.g., a member leaves) to ensure forward secrecy.
func (b *GroupSessionBuilder) Rotate() ([]byte, error) {
	return b.inner.Rotate()
}

// Process updates the local sender key record using a received distribution message.
// This allows the local user to decrypt messages sent by the creator of the distribution message.
func (b *GroupSessionBuilder) Process(distribution []byte) error {
	return b.inner.Process(distribution)
}

// GroupCipher provides Encrypt/Decrypt for Sender Key group messages for a (group, sender) tuple.
// It uses the Sender Keys protocol, where each sender has their own key ratchet.
type GroupCipher struct {
	inner *senderkeys.Cipher
}

// NewGroupCipher constructs a GroupCipher for the given store and sender key name.
func NewGroupCipher(s ProtocolStore, name SenderKeyName) *GroupCipher {
	return &GroupCipher{inner: senderkeys.NewCipher(s, name)}
}

// Encrypt encrypts plaintext using the current sender key state.
// It returns a SenderKeyMessage. The sender key state is advanced after encryption.
func (c *GroupCipher) Encrypt(plaintext []byte) ([]byte, error) {
	return c.inner.Encrypt(plaintext)
}

// Decrypt decrypts a sender key group message.
// It updates the sender key state on success to prevent replay and maintain synchronization.
func (c *GroupCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	return c.inner.Decrypt(ciphertext)
}
