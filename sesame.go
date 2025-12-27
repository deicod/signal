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
type SesameManager struct {
	inner *sesame.Manager
}

// NewSesameManager constructs a SesameManager bound to store and local address.
func NewSesameManager(s ProtocolStore, local Address, maxLatency time.Duration) *SesameManager {
	return &SesameManager{inner: sesame.NewManager(s, local, maxLatency)}
}

// ApplyDeviceList updates the roster for userID to match the provided device list.
func (m *SesameManager) ApplyDeviceList(userID string, devices []SesameDevice, now time.Time) error {
	return m.inner.ApplyDeviceList(userID, devices, now)
}

// MarkUserStale marks userID stale at now.
func (m *SesameManager) MarkUserStale(userID string, now time.Time) error {
	return m.inner.MarkUserStale(userID, now)
}

// MarkDeviceStale marks addr stale at now.
func (m *SesameManager) MarkDeviceStale(addr Address, now time.Time) error {
	return m.inner.MarkDeviceStale(addr, now)
}

// TouchDevice marks addr as non-stale, creating records if needed.
func (m *SesameManager) TouchDevice(addr Address) error {
	return m.inner.TouchDevice(addr)
}

// NonStaleDevices returns the non-stale device addresses for userID, excluding the local device.
func (m *SesameManager) NonStaleDevices(userID string) ([]Address, error) {
	return m.inner.NonStaleDevices(userID)
}

// PruneStale deletes stale user/device records older than maxLatency, along with their sessions.
func (m *SesameManager) PruneStale(now time.Time) error {
	return m.inner.PruneStale(now)
}
