package store

import "github.com/deicod/signal/keys"

// IdentityKeyStore stores local identity keys and trusted remote identities.
type IdentityKeyStore interface {
	GetIdentityKeyPair() (*keys.IdentityKeyPair, error)
	GetLocalRegistrationID() (uint32, error)
	SaveIdentity(address Address, identityKey *keys.IdentityKey) error
	IsTrustedIdentity(address Address, identityKey *keys.IdentityKey, direction Direction) bool
	GetIdentity(address Address) (*keys.IdentityKey, error)
}

// PreKeyStore stores one-time pre-keys.
type PreKeyStore interface {
	LoadPreKey(id uint32) (*keys.PreKey, error)
	StorePreKey(id uint32, preKey *keys.PreKey) error
	ContainsPreKey(id uint32) bool
	RemovePreKey(id uint32) error
}

// SignedPreKeyStore stores signed pre-keys.
type SignedPreKeyStore interface {
	LoadSignedPreKey(id uint32) (*keys.SignedPreKey, error)
	StoreSignedPreKey(id uint32, signedPreKey *keys.SignedPreKey) error
	ContainsSignedPreKey(id uint32) bool
	RemoveSignedPreKey(id uint32) error
}

// SessionRecord is an opaque container for session persistence.
// Implementations can store any serialized or in-memory session representation.
type SessionRecord struct {
	Data any
}

// SessionStore stores session records by address.
type SessionStore interface {
	LoadSession(address Address) (*SessionRecord, error)
	StoreSession(address Address, record *SessionRecord) error
	ContainsSession(address Address) bool
	DeleteSession(address Address) error
	DeleteAllSessions(name string) error
}

// ProtocolStore combines all store interfaces.
type ProtocolStore interface {
	IdentityKeyStore
	PreKeyStore
	SignedPreKeyStore
	SessionStore
}
