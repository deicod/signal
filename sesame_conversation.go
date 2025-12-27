package signal

import (
	"context"
	"time"

	"github.com/deicod/signal/sesame"
)

// SesameRosterProvider supplies device rosters and pre-key bundles for encryption.
type SesameRosterProvider = sesame.RosterProvider

// MissingBundleError reports missing pre-key bundles for devices without sessions.
type MissingBundleError = sesame.MissingBundleError

var (
	// ErrRosterChanged signals that the roster should be refreshed before retrying.
	ErrRosterChanged = sesame.ErrRosterChanged
	// ErrSendAttemptsExceeded indicates a roster refresh loop exceeded its bounds.
	ErrSendAttemptsExceeded = sesame.ErrSendAttemptsExceeded
)

// SesameConversation coordinates multi-device session encryption/decryption for a user.
type SesameConversation struct {
	inner *sesame.Conversation
}

// NewSesameConversation constructs a SesameConversation bound to store and local address.
func NewSesameConversation(s ProtocolStore, local Address, maxLatency time.Duration) *SesameConversation {
	return &SesameConversation{inner: sesame.NewConversation(s, local, maxLatency)}
}

// SetMaxSendAttempts sets the roster refresh bound for EncryptWithRoster.
func (c *SesameConversation) SetMaxSendAttempts(n int) {
	c.inner.SetMaxSendAttempts(n)
}

// MaxSendAttempts returns the roster refresh bound for EncryptWithRoster.
func (c *SesameConversation) MaxSendAttempts() int {
	return c.inner.MaxSendAttempts()
}

// Encrypt encrypts plaintext to non-stale devices for userID using existing sessions,
// bootstrapping missing sessions with provided pre-key bundles.
func (c *SesameConversation) Encrypt(userID string, plaintext []byte, bundles map[Address]*PreKeyBundle) (map[Address][]byte, error) {
	return c.inner.Encrypt(userID, plaintext, bundles)
}

// EncryptWithRoster refreshes the roster before encrypting, retrying when the provider
// signals ErrRosterChanged.
func (c *SesameConversation) EncryptWithRoster(ctx context.Context, userID string, plaintext []byte, provider SesameRosterProvider, now time.Time) (map[Address][]byte, error) {
	return c.inner.EncryptWithRoster(ctx, userID, plaintext, provider, now)
}

// Decrypt decrypts ciphertext from addr and marks the device active on success.
// A non-nil plaintext may be returned alongside a roster update error.
func (c *SesameConversation) Decrypt(addr Address, ciphertext []byte) ([]byte, error) {
	return c.inner.Decrypt(addr, ciphertext)
}
