package memory

import (
	"bytes"
	"crypto/subtle"
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
	kyberKeys  map[uint32]*keys.KyberPreKey
	sessions   map[store.Address]*store.SessionRecord
	senderKeys map[store.SenderKeyName]*store.SenderKeyRecord
	sesame     *store.SesameRecord
}

// NewStore initializes an empty in-memory store.
func NewStore(identity *keys.IdentityKeyPair, registrationID uint32) *Store {
	return &Store{
		identityKeyPair:     identity,
		localRegistrationID: registrationID,
		identities:          make(map[store.Address]*keys.IdentityKey),
		preKeys:             make(map[uint32]*keys.PreKey),
		signedKeys:          make(map[uint32]*keys.SignedPreKey),
		kyberKeys:           make(map[uint32]*keys.KyberPreKey),
		sessions:            make(map[store.Address]*store.SessionRecord),
		senderKeys:          make(map[store.SenderKeyName]*store.SenderKeyRecord),
		sesame:              nil,
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
	if identityKey == nil {
		delete(m.identities, addr)
		return nil
	}
	clone := *identityKey
	if isZeroKey32(clone.SigningPublic) {
		if existing := m.identities[addr]; existing != nil && !isZeroKey32(existing.SigningPublic) {
			clone.SigningPublic = existing.SigningPublic
		}
	}
	m.identities[addr] = &clone
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
	if existing == nil || identityKey == nil {
		return false
	}
	dhOK := subtle.ConstantTimeCompare(existing.PublicKey[:], identityKey.PublicKey[:]) == 1
	if isZeroKey32(existing.SigningPublic) || isZeroKey32(identityKey.SigningPublic) {
		return dhOK
	}
	signingOK := subtle.ConstantTimeCompare(existing.SigningPublic[:], identityKey.SigningPublic[:]) == 1
	return signingOK && dhOK
}

// GetIdentity retrieves a stored identity for a remote address.
func (m *Store) GetIdentity(addr store.Address) (*keys.IdentityKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.identities[addr]
	if !ok {
		return nil, nil
	}
	if id == nil {
		return nil, nil
	}
	clone := *id
	return &clone, nil
}

func isZeroKey32(key [32]byte) bool {
	for _, b := range key {
		if b != 0 {
			return false
		}
	}
	return true
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

// LoadKyberPreKey returns a Kyber pre-key by ID.
func (m *Store) LoadKyberPreKey(id uint32) (*keys.KyberPreKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	pk, ok := m.kyberKeys[id]
	if !ok {
		return nil, nil
	}
	return pk, nil
}

// StoreKyberPreKey saves a Kyber pre-key by ID.
func (m *Store) StoreKyberPreKey(id uint32, kyberPreKey *keys.KyberPreKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.kyberKeys[id] = kyberPreKey
	return nil
}

// ContainsKyberPreKey returns true if a Kyber pre-key exists.
func (m *Store) ContainsKyberPreKey(id uint32) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.kyberKeys[id]
	return ok
}

// RemoveKyberPreKey deletes a Kyber pre-key by ID.
func (m *Store) RemoveKyberPreKey(id uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.kyberKeys, id)
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
	if rec == nil {
		return nil, nil
	}
	return &store.SessionRecord{
		Data: bytes.Clone(rec.Data),
	}, nil
}

// StoreSession saves a session record.
func (m *Store) StoreSession(addr store.Address, record *store.SessionRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if record == nil {
		delete(m.sessions, addr)
		return nil
	}
	m.sessions[addr] = &store.SessionRecord{Data: bytes.Clone(record.Data)}
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

// LoadSenderKey returns a sender key record for the given name.
func (m *Store) LoadSenderKey(name store.SenderKeyName) (*store.SenderKeyRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.senderKeys[name]
	if !ok {
		return nil, nil
	}
	if rec == nil {
		return nil, nil
	}
	return &store.SenderKeyRecord{
		Data: bytes.Clone(rec.Data),
	}, nil
}

// StoreSenderKey saves a sender key record.
func (m *Store) StoreSenderKey(name store.SenderKeyName, record *store.SenderKeyRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if record == nil {
		delete(m.senderKeys, name)
		return nil
	}
	m.senderKeys[name] = &store.SenderKeyRecord{Data: bytes.Clone(record.Data)}
	return nil
}

// ContainsSenderKey returns true if a sender key record exists.
func (m *Store) ContainsSenderKey(name store.SenderKeyName) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.senderKeys[name]
	return ok
}

// DeleteSenderKey removes a sender key record.
func (m *Store) DeleteSenderKey(name store.SenderKeyName) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.senderKeys, name)
	return nil
}

// DeleteAllSenderKeys removes all sender key records for a group.
func (m *Store) DeleteAllSenderKeys(group string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for name := range m.senderKeys {
		if name.Group == group {
			delete(m.senderKeys, name)
		}
	}
	return nil
}

// LoadSesameState returns the stored Sesame roster state.
func (m *Store) LoadSesameState() (*store.SesameRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.sesame == nil {
		return nil, nil
	}
	return &store.SesameRecord{
		Data: bytes.Clone(m.sesame.Data),
	}, nil
}

// StoreSesameState saves the Sesame roster state.
func (m *Store) StoreSesameState(record *store.SesameRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if record == nil {
		m.sesame = nil
		return nil
	}
	m.sesame = &store.SesameRecord{Data: bytes.Clone(record.Data)}
	return nil
}

// DeleteSesameState removes the stored Sesame roster state.
func (m *Store) DeleteSesameState() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sesame = nil
	return nil
}
