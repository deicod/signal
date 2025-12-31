package signal

import (
	"time"

	"github.com/deicod/signal/sesame"
)

// SesameDevice describes a device entry from a server roster response.
type SesameDevice = sesame.Device

// IdentityChangedError indicates the server roster presented identity keys that do not
// match the locally trusted identity store.
type IdentityChangedError = sesame.IdentityChangedError

// SesameManager tracks a Sesame roster for the local device and applies staleness rules.
// It manages the list of active devices for users, allowing for multi-device support.
type SesameManager struct {
	inner *sesame.Manager
}

// NewSesameManager constructs a SesameManager bound to store and local address.
// maxLatency defines how long a device can be inactive before being considered stale.
func NewSesameManager(s ProtocolStore, local Address, maxLatency time.Duration) *SesameManager {
	return &SesameManager{inner: sesame.NewManager(s, local, maxLatency)}
}

// ApplyDeviceList updates the roster for userID to match the provided device list.
// New devices are added, and missing devices are marked as stale or removed according to policy.
func (m *SesameManager) ApplyDeviceList(userID string, devices []SesameDevice, now time.Time) error {
	return m.inner.ApplyDeviceList(userID, devices, now)
}

// MarkUserStale marks all devices of userID as stale at the given time.
// This is typically done when an identity change is detected or other security events occur.
func (m *SesameManager) MarkUserStale(userID string, now time.Time) error {
	return m.inner.MarkUserStale(userID, now)
}

// MarkDeviceStale marks a specific device (addr) as stale at the given time.
func (m *SesameManager) MarkDeviceStale(addr Address, now time.Time) error {
	return m.inner.MarkDeviceStale(addr, now)
}

// TouchDevice marks addr as non-stale (active), creating records if needed.
// This should be called when a message is successfully received from or sent to the device.
func (m *SesameManager) TouchDevice(addr Address) error {
	return m.inner.TouchDevice(addr)
}

// NonStaleDevices returns the non-stale device addresses for userID, excluding the local device.
// This list is used to determine which devices to send messages to.
func (m *SesameManager) NonStaleDevices(userID string) ([]Address, error) {
	return m.inner.NonStaleDevices(userID)
}

// PruneStale deletes stale user/device records older than maxLatency, along with their sessions.
// This cleans up storage and removes devices that haven't been seen for a long time.
func (m *SesameManager) PruneStale(now time.Time) error {
	return m.inner.PruneStale(now)
}
