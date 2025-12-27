package sesame

import (
	"fmt"
	"sort"
	"sync"
	"time"

	signalerrors "github.com/deicod/signal/errors"
	"github.com/deicod/signal/keys"
	"github.com/deicod/signal/store"
)

// Device describes a device entry from a server roster response.
//
// IdentityKey is optional; if provided and it does not match the stored identity,
// the corresponding session is deleted and ApplyDeviceList returns an error that
// wraps errors.ErrUntrustedIdentity.
type Device struct {
	DeviceID    uint32
	IdentityKey *keys.IdentityKey
}

// Manager tracks a Sesame roster for the local device and applies staleness rules.
type Manager struct {
	mu sync.Mutex

	store      store.ProtocolStore
	local      store.Address
	maxLatency time.Duration
}

// NewManager constructs a Manager bound to store and local address.
func NewManager(s store.ProtocolStore, local store.Address, maxLatency time.Duration) *Manager {
	return &Manager{
		store:      s,
		local:      local,
		maxLatency: maxLatency,
	}
}

// ApplyDeviceList updates the roster for userID to match the provided device list.
//
// Devices present in the current roster but not in devices are marked stale. Devices in devices
// are created or un-staled.
func (m *Manager) ApplyDeviceList(userID string, devices []Device, now time.Time) error {
	if m == nil || m.store == nil {
		return fmt.Errorf("sesame manager not initialized")
	}
	if userID == "" {
		return fmt.Errorf("%w: user id is empty", signalerrors.ErrInvalidMessage)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	state, err := m.loadState()
	if err != nil {
		return err
	}

	user := state.getOrCreateUser(userID)
	user.stale = false
	user.staleSince = time.Time{}

	deviceSet := make(map[uint32]Device, len(devices))
	for _, d := range devices {
		if _, ok := deviceSet[d.DeviceID]; ok {
			return fmt.Errorf("%w: duplicate device id %d", signalerrors.ErrInvalidMessage, d.DeviceID)
		}
		deviceSet[d.DeviceID] = d
	}

	for deviceID, rec := range user.devices {
		if _, ok := deviceSet[deviceID]; ok {
			continue
		}
		if rec == nil {
			user.devices[deviceID] = &deviceRecord{stale: true, staleSince: now.UTC()}
			continue
		}
		if !rec.stale {
			rec.stale = true
			rec.staleSince = now.UTC()
		}
	}

	var identityChanged []store.Address

	for deviceID, dev := range deviceSet {
		if userID == m.local.Name && deviceID == m.local.Device {
			continue
		}
		rec := user.devices[deviceID]
		if rec == nil {
			rec = &deviceRecord{}
			user.devices[deviceID] = rec
		}
		rec.stale = false
		rec.staleSince = time.Time{}

		if dev.IdentityKey != nil {
			addr := store.Address{Name: userID, Device: deviceID}
			existing, err := m.store.GetIdentity(addr)
			if err != nil {
				return fmt.Errorf("load identity: %w", err)
			}
			if existing != nil && !identityEqual(existing, dev.IdentityKey) {
				if err := m.store.DeleteSession(addr); err != nil {
					return fmt.Errorf("delete session: %w", err)
				}
				identityChanged = append(identityChanged, addr)
			}
		}
	}

	if err := m.persistState(state); err != nil {
		return err
	}

	if len(identityChanged) > 0 {
		sort.Slice(identityChanged, func(i, j int) bool {
			if identityChanged[i].Name != identityChanged[j].Name {
				return identityChanged[i].Name < identityChanged[j].Name
			}
			return identityChanged[i].Device < identityChanged[j].Device
		})
		return &IdentityChangedError{Addresses: identityChanged}
	}

	return nil
}

// MarkUserStale marks userID stale at now.
func (m *Manager) MarkUserStale(userID string, now time.Time) error {
	if m == nil || m.store == nil {
		return fmt.Errorf("sesame manager not initialized")
	}
	if userID == "" {
		return fmt.Errorf("%w: user id is empty", signalerrors.ErrInvalidMessage)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	state, err := m.loadState()
	if err != nil {
		return err
	}

	user := state.getOrCreateUser(userID)
	if !user.stale {
		user.stale = true
		user.staleSince = now.UTC()
	}

	return m.persistState(state)
}

// MarkDeviceStale marks addr stale at now.
func (m *Manager) MarkDeviceStale(addr store.Address, now time.Time) error {
	if m == nil || m.store == nil {
		return fmt.Errorf("sesame manager not initialized")
	}
	if addr.Name == "" || addr.Device == 0 {
		return fmt.Errorf("%w: invalid device address", signalerrors.ErrInvalidMessage)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	state, err := m.loadState()
	if err != nil {
		return err
	}

	user := state.getOrCreateUser(addr.Name)
	if addr.Name == m.local.Name && addr.Device == m.local.Device {
		return nil
	}

	dev := user.devices[addr.Device]
	if dev == nil {
		dev = &deviceRecord{}
		user.devices[addr.Device] = dev
	}
	if !dev.stale {
		dev.stale = true
		dev.staleSince = now.UTC()
	}

	return m.persistState(state)
}

// TouchDevice marks addr as non-stale, creating records if needed.
func (m *Manager) TouchDevice(addr store.Address) error {
	if m == nil || m.store == nil {
		return fmt.Errorf("sesame manager not initialized")
	}
	if addr.Name == "" || addr.Device == 0 {
		return fmt.Errorf("%w: invalid device address", signalerrors.ErrInvalidMessage)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	state, err := m.loadState()
	if err != nil {
		return err
	}

	user := state.getOrCreateUser(addr.Name)
	user.stale = false
	user.staleSince = time.Time{}
	if addr.Name == m.local.Name && addr.Device == m.local.Device {
		return m.persistState(state)
	}

	dev := user.devices[addr.Device]
	if dev == nil {
		dev = &deviceRecord{}
		user.devices[addr.Device] = dev
	}
	dev.stale = false
	dev.staleSince = time.Time{}

	return m.persistState(state)
}

// NonStaleDevices returns the non-stale device addresses for userID, excluding the local device.
func (m *Manager) NonStaleDevices(userID string) ([]store.Address, error) {
	if m == nil || m.store == nil {
		return nil, fmt.Errorf("sesame manager not initialized")
	}
	if userID == "" {
		return nil, fmt.Errorf("%w: user id is empty", signalerrors.ErrInvalidMessage)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	state, err := m.loadState()
	if err != nil {
		return nil, err
	}

	user := state.user(userID)
	if user == nil || user.stale {
		return nil, nil
	}

	deviceIDs := make([]uint32, 0, len(user.devices))
	for deviceID, rec := range user.devices {
		if rec == nil || rec.stale {
			continue
		}
		if userID == m.local.Name && deviceID == m.local.Device {
			continue
		}
		deviceIDs = append(deviceIDs, deviceID)
	}
	sort.Slice(deviceIDs, func(i, j int) bool { return deviceIDs[i] < deviceIDs[j] })

	out := make([]store.Address, 0, len(deviceIDs))
	for _, deviceID := range deviceIDs {
		out = append(out, store.Address{Name: userID, Device: deviceID})
	}
	return out, nil
}

// PruneStale deletes stale user/device records older than maxLatency, along with their sessions.
func (m *Manager) PruneStale(now time.Time) error {
	if m == nil || m.store == nil {
		return fmt.Errorf("sesame manager not initialized")
	}
	if m.maxLatency <= 0 {
		return fmt.Errorf("%w: max latency must be > 0", signalerrors.ErrInvalidMessage)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	state, err := m.loadState()
	if err != nil {
		return err
	}

	for userID, user := range state.users {
		if user == nil {
			delete(state.users, userID)
			continue
		}

		if user.stale && shouldPrune(now, user.staleSince, m.maxLatency) {
			for deviceID := range user.devices {
				addr := store.Address{Name: userID, Device: deviceID}
				_ = m.store.SaveIdentity(addr, nil)
			}
			if err := m.store.DeleteAllSessions(userID); err != nil {
				return fmt.Errorf("delete all sessions: %w", err)
			}
			delete(state.users, userID)
			continue
		}

		for deviceID, dev := range user.devices {
			if dev == nil {
				delete(user.devices, deviceID)
				continue
			}
			if !dev.stale || !shouldPrune(now, dev.staleSince, m.maxLatency) {
				continue
			}

			addr := store.Address{Name: userID, Device: deviceID}
			if err := m.store.DeleteSession(addr); err != nil {
				return fmt.Errorf("delete session: %w", err)
			}
			_ = m.store.SaveIdentity(addr, nil)
			delete(user.devices, deviceID)
		}

		if len(user.devices) == 0 && !user.stale {
			delete(state.users, userID)
		}
	}

	return m.persistState(state)
}

// IdentityChangedError indicates the server roster presented identity keys that do not
// match the locally trusted identity store.
type IdentityChangedError struct {
	Addresses []store.Address
}

func (e *IdentityChangedError) Error() string {
	if e == nil || len(e.Addresses) == 0 {
		return "sesame: identity changed"
	}
	return fmt.Sprintf("sesame: identity changed for %d devices", len(e.Addresses))
}

func (e *IdentityChangedError) Unwrap() error {
	return signalerrors.ErrUntrustedIdentity
}

func (m *Manager) loadState() (*State, error) {
	rec, err := m.store.LoadSesameState()
	if err != nil {
		return nil, fmt.Errorf("load sesame state: %w", err)
	}
	if rec == nil || len(rec.Data) == 0 {
		return NewState(), nil
	}
	state, err := DeserializeState(rec.Data)
	if err != nil {
		return nil, err
	}
	return state, nil
}

func (m *Manager) persistState(state *State) error {
	if state == nil {
		return fmt.Errorf("%w: sesame state is nil", signalerrors.ErrInvalidMessage)
	}
	data, err := state.Serialize()
	if err != nil {
		return err
	}
	return m.store.StoreSesameState(&store.SesameRecord{Data: data})
}

func shouldPrune(now, staleSince time.Time, maxLatency time.Duration) bool {
	if staleSince.IsZero() {
		return false
	}
	if now.Before(staleSince) {
		return false
	}
	return now.Sub(staleSince) >= maxLatency
}

func identityEqual(a, b *keys.IdentityKey) bool {
	if a == nil || b == nil {
		return false
	}
	return a.PublicKey == b.PublicKey && a.SigningPublic == b.SigningPublic
}
