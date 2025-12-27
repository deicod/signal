package sesame

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	signalerrors "github.com/deicod/signal/errors"
	"github.com/deicod/signal/keys"
	"github.com/deicod/signal/session"
	"github.com/deicod/signal/store"
)

// DefaultMaxSendAttempts bounds roster refresh loops during encryption.
const DefaultMaxSendAttempts = 3

// ErrRosterChanged signals that the roster should be refreshed before retrying.
var ErrRosterChanged = errors.New("sesame: roster changed")

// ErrSendAttemptsExceeded indicates a roster refresh loop exceeded its bounds.
var ErrSendAttemptsExceeded = errors.New("sesame: send attempts exceeded")

// MissingBundleError reports missing pre-key bundles for devices without sessions.
type MissingBundleError struct {
	Addresses []store.Address
}

func (e *MissingBundleError) Error() string {
	if e == nil || len(e.Addresses) == 0 {
		return "sesame: missing pre-key bundles"
	}
	return fmt.Sprintf("sesame: missing pre-key bundles for %d devices", len(e.Addresses))
}

func (e *MissingBundleError) Unwrap() error {
	return signalerrors.ErrNoSession
}

// RosterProvider supplies device rosters and pre-key bundles for encryption.
type RosterProvider interface {
	DeviceList(ctx context.Context, userID string) ([]Device, error)
	PreKeyBundle(ctx context.Context, addr store.Address) (*keys.PreKeyBundle, error)
}

// Conversation coordinates multi-device session encryption/decryption for a user.
type Conversation struct {
	store           store.ProtocolStore
	manager         *Manager
	maxSendAttempts int
}

// NewConversation constructs a Conversation bound to store and local address.
func NewConversation(s store.ProtocolStore, local store.Address, maxLatency time.Duration) *Conversation {
	return &Conversation{
		store:           s,
		manager:         NewManager(s, local, maxLatency),
		maxSendAttempts: DefaultMaxSendAttempts,
	}
}

// SetMaxSendAttempts sets the roster refresh bound for EncryptWithRoster.
func (c *Conversation) SetMaxSendAttempts(n int) {
	if c == nil {
		return
	}
	c.maxSendAttempts = n
}

// MaxSendAttempts returns the roster refresh bound for EncryptWithRoster.
func (c *Conversation) MaxSendAttempts() int {
	if c == nil {
		return 0
	}
	return c.maxSendAttempts
}

// Encrypt encrypts plaintext to non-stale devices for userID using existing sessions,
// bootstrapping missing sessions with provided pre-key bundles.
func (c *Conversation) Encrypt(userID string, plaintext []byte, bundles map[store.Address]*keys.PreKeyBundle) (map[store.Address][]byte, error) {
	if c == nil || c.store == nil || c.manager == nil {
		return nil, fmt.Errorf("sesame conversation not initialized")
	}
	if userID == "" {
		return nil, fmt.Errorf("%w: user id is empty", signalerrors.ErrInvalidMessage)
	}

	addrs, err := c.manager.NonStaleDevices(userID)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return map[store.Address][]byte{}, nil
	}

	needsBundle := make(map[store.Address]bool, len(addrs))
	missing := make([]store.Address, 0)
	for _, addr := range addrs {
		ready, err := c.sessionReady(addr)
		if err != nil {
			return nil, err
		}
		if ready {
			continue
		}
		bundle := bundles[addr]
		if bundle == nil {
			missing = append(missing, addr)
			continue
		}
		needsBundle[addr] = true
	}
	if len(missing) > 0 {
		sort.Slice(missing, func(i, j int) bool {
			if missing[i].Name != missing[j].Name {
				return missing[i].Name < missing[j].Name
			}
			return missing[i].Device < missing[j].Device
		})
		return nil, &MissingBundleError{Addresses: missing}
	}

	out := make(map[store.Address][]byte, len(addrs))
	for _, addr := range addrs {
		cipher := session.NewWireCipher(c.store, addr)
		var ct []byte
		var err error
		if needsBundle[addr] {
			ct, err = cipher.EncryptWithPreKeyBundle(bundles[addr], plaintext)
		} else {
			ct, err = cipher.Encrypt(plaintext)
			if errors.Is(err, signalerrors.ErrNoSession) && bundles[addr] != nil {
				ct, err = cipher.EncryptWithPreKeyBundle(bundles[addr], plaintext)
			}
		}
		if err != nil {
			return nil, err
		}
		out[addr] = ct
	}

	return out, nil
}

// EncryptWithRoster refreshes the roster before encrypting, retrying when the provider
// signals ErrRosterChanged.
func (c *Conversation) EncryptWithRoster(ctx context.Context, userID string, plaintext []byte, provider RosterProvider, now time.Time) (map[store.Address][]byte, error) {
	if c == nil || c.store == nil || c.manager == nil {
		return nil, fmt.Errorf("sesame conversation not initialized")
	}
	if provider == nil {
		return nil, fmt.Errorf("sesame roster provider is nil")
	}
	if userID == "" {
		return nil, fmt.Errorf("%w: user id is empty", signalerrors.ErrInvalidMessage)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	attempts := c.maxSendAttempts
	if attempts <= 0 {
		attempts = DefaultMaxSendAttempts
	}

	for attempt := 0; attempt < attempts; attempt++ {
		devices, err := provider.DeviceList(ctx, userID)
		if err != nil {
			if errors.Is(err, ErrRosterChanged) {
				continue
			}
			return nil, err
		}

		if err := c.manager.ApplyDeviceList(userID, devices, now); err != nil {
			return nil, err
		}

		addrs, err := c.manager.NonStaleDevices(userID)
		if err != nil {
			return nil, err
		}

		bundles := make(map[store.Address]*keys.PreKeyBundle, len(addrs))
		missing := make([]store.Address, 0)
		retry := false

		for _, addr := range addrs {
			ready, err := c.sessionReady(addr)
			if err != nil {
				return nil, err
			}
			if ready {
				continue
			}
			bundle, err := provider.PreKeyBundle(ctx, addr)
			if err != nil {
				if errors.Is(err, ErrRosterChanged) {
					retry = true
					break
				}
				return nil, err
			}
			if bundle == nil {
				missing = append(missing, addr)
				continue
			}
			bundles[addr] = bundle
		}

		if retry {
			continue
		}
		if len(missing) > 0 {
			sort.Slice(missing, func(i, j int) bool {
				if missing[i].Name != missing[j].Name {
					return missing[i].Name < missing[j].Name
				}
				return missing[i].Device < missing[j].Device
			})
			return nil, &MissingBundleError{Addresses: missing}
		}

		return c.Encrypt(userID, plaintext, bundles)
	}

	return nil, ErrSendAttemptsExceeded
}

// Decrypt decrypts ciphertext from addr and marks the device active on success.
// A non-nil plaintext may be returned alongside a roster update error.
func (c *Conversation) Decrypt(addr store.Address, ciphertext []byte) ([]byte, error) {
	if c == nil || c.store == nil || c.manager == nil {
		return nil, fmt.Errorf("sesame conversation not initialized")
	}
	if addr.Name == "" || addr.Device == 0 {
		return nil, fmt.Errorf("%w: invalid device address", signalerrors.ErrInvalidMessage)
	}

	cipher := session.NewWireCipher(c.store, addr)
	plaintext, err := cipher.Decrypt(ciphertext)
	if err != nil {
		return nil, err
	}

	if err := c.manager.TouchDevice(addr); err != nil {
		return plaintext, err
	}

	return plaintext, nil
}

func (c *Conversation) sessionReady(addr store.Address) (bool, error) {
	rec, err := c.store.LoadSession(addr)
	if err != nil {
		return false, fmt.Errorf("load session record: %w", err)
	}
	if rec == nil || len(rec.Data) == 0 {
		return false, nil
	}
	record, err := session.DeserializeRecord(rec.Data)
	if err != nil {
		return false, fmt.Errorf("%w: deserialize session record: %v", signalerrors.ErrInvalidMessage, err)
	}
	if record.Current() == nil {
		return false, fmt.Errorf("%w: invalid session record for %v", signalerrors.ErrInvalidMessage, addr)
	}
	return true, nil
}
