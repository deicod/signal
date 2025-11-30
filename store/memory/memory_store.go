package memory

import (
	"sync"

	"github.com/deicod/signal/keys"
	"github.com/deicod/signal/store"
)

// Store is a thread-safe in-memory implementation of ProtocolStore.
type Store struct {
	mu sync.RWMutex

	identityKeyPair     *keys.IdentityKeyPair
	localRegistrationID uint32

	identities map[store.Address]*keys.IdentityKey
	preKeys    map[uint32]*keys.PreKey
	signedKeys map[uint32]*keys.SignedPreKey
	sessions   map[store.Address]*store.SessionRecord
}

// NewStore initializes an empty in-memory store.
func NewStore(identity *keys.IdentityKeyPair, registrationID uint32) *Store {
	return &Store{
		identityKeyPair:     identity,
		localRegistrationID: registrationID,
		identities:          make(map[store.Address]*keys.IdentityKey),
		preKeys:             make(map[uint32]*keys.PreKey),
		signedKeys:          make(map[uint32]*keys.SignedPreKey),
		sessions:            make(map[store.Address]*store.SessionRecord),
	}
}

// GetIdentityKeyPair returns the local identity key pair.
func (m *Store) GetIdentityKeyPair() (*keys.IdentityKeyPair, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.identityKeyPair, nil
}

// GetLocalRegistrationID returns the local registration ID.
func (m *Store) GetLocalRegistrationID() (uint32, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.localRegistrationID, nil
}

// SaveIdentity stores the trusted identity for a remote address.
func (m *Store) SaveIdentity(addr store.Address, identityKey *keys.IdentityKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.identities[addr] = identityKey
	return nil
}

// IsTrustedIdentity compares the provided identity with the stored identity, accepting unknown peers.
func (m *Store) IsTrustedIdentity(addr store.Address, identityKey *keys.IdentityKey, _ store.Direction) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	existing, ok := m.identities[addr]
	if !ok {
		return true // First seen, accept by default.
	}
	return existing.SigningPublic == identityKey.SigningPublic && existing.PublicKey == identityKey.PublicKey
}

// GetIdentity retrieves a stored identity for a remote address.
func (m *Store) GetIdentity(addr store.Address) (*keys.IdentityKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.identities[addr]
	if !ok {
		return nil, nil
	}
	return id, nil
}

// LoadPreKey returns a pre-key by ID.
func (m *Store) LoadPreKey(id uint32) (*keys.PreKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	pk, ok := m.preKeys[id]
	if !ok {
		return nil, nil
	}
	return pk, nil
}

// StorePreKey saves a pre-key by ID.
func (m *Store) StorePreKey(id uint32, preKey *keys.PreKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.preKeys[id] = preKey
	return nil
}

// ContainsPreKey returns true if a pre-key exists.
func (m *Store) ContainsPreKey(id uint32) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.preKeys[id]
	return ok
}

// RemovePreKey deletes a pre-key by ID.
func (m *Store) RemovePreKey(id uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.preKeys, id)
	return nil
}

// LoadSignedPreKey returns a signed pre-key by ID.
func (m *Store) LoadSignedPreKey(id uint32) (*keys.SignedPreKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	pk, ok := m.signedKeys[id]
	if !ok {
		return nil, nil
	}
	return pk, nil
}

// StoreSignedPreKey saves a signed pre-key by ID.
func (m *Store) StoreSignedPreKey(id uint32, signedPreKey *keys.SignedPreKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.signedKeys[id] = signedPreKey
	return nil
}

// ContainsSignedPreKey returns true if a signed pre-key exists.
func (m *Store) ContainsSignedPreKey(id uint32) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.signedKeys[id]
	return ok
}

// RemoveSignedPreKey deletes a signed pre-key by ID.
func (m *Store) RemoveSignedPreKey(id uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.signedKeys, id)
	return nil
}

// LoadSession returns a session record for the given address.
func (m *Store) LoadSession(addr store.Address) (*store.SessionRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.sessions[addr]
	if !ok {
		return nil, nil
	}
	return rec, nil
}

// StoreSession saves a session record.
func (m *Store) StoreSession(addr store.Address, record *store.SessionRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[addr] = record
	return nil
}

// ContainsSession returns true if a session exists.
func (m *Store) ContainsSession(addr store.Address) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.sessions[addr]
	return ok
}

// DeleteSession removes a single session.
func (m *Store) DeleteSession(addr store.Address) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, addr)
	return nil
}

// DeleteAllSessions removes sessions for a given name.
func (m *Store) DeleteAllSessions(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for addr := range m.sessions {
		if addr.Name == name {
			delete(m.sessions, addr)
		}
	}
	return nil
}
