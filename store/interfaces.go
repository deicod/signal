package store

import (
	"time"

	"github.com/deicod/signal/keys"
)

// IdentityKeyStore stores local identity keys and trusted remote identities.
// Implementations must ensure data integrity and persistence.
type IdentityKeyStore interface {
	// GetIdentityKeyPair retrieves the local identity key pair.
	GetIdentityKeyPair() (*keys.IdentityKeyPair, error)
	// GetLocalRegistrationID retrieves the local registration ID.
	GetLocalRegistrationID() (uint32, error)
	// SaveIdentity stores a remote identity key.
	// It should update the existing record if one exists for the address.
	SaveIdentity(address Address, identityKey *keys.IdentityKey) error
	// IsTrustedIdentity returns true if the identity key is trusted for the given address.
	// It should handle "trust on first use" (TOFU) or other trust policies.
	IsTrustedIdentity(address Address, identityKey *keys.IdentityKey, direction Direction) bool
	// GetIdentity retrieves the trusted identity key for a remote address.
	GetIdentity(address Address) (*keys.IdentityKey, error)
}

// PreKeyStore stores one-time pre-keys.
// Keys should be removed after use.
type PreKeyStore interface {
	// LoadPreKey retrieves a one-time pre-key by ID.
	LoadPreKey(id uint32) (*keys.PreKey, error)
	// StorePreKey stores a one-time pre-key.
	StorePreKey(id uint32, preKey *keys.PreKey) error
	// ContainsPreKey checks if a pre-key exists.
	ContainsPreKey(id uint32) bool
	// RemovePreKey deletes a pre-key.
	RemovePreKey(id uint32) error
}

// SignedPreKeyStore stores signed pre-keys.
// These are long-lived and rotated periodically.
type SignedPreKeyStore interface {
	// LoadSignedPreKey retrieves a signed pre-key by ID.
	LoadSignedPreKey(id uint32) (*keys.SignedPreKey, error)
	// StoreSignedPreKey stores a signed pre-key.
	StoreSignedPreKey(id uint32, signedPreKey *keys.SignedPreKey) error
	// ContainsSignedPreKey checks if a signed pre-key exists.
	ContainsSignedPreKey(id uint32) bool
	// RemoveSignedPreKey deletes a signed pre-key.
	RemoveSignedPreKey(id uint32) error
	// SignedPreKeyExpired reports whether the signed pre-key is expired at the provided time.
	SignedPreKeyExpired(signedPreKey *keys.SignedPreKey, now time.Time) bool
}

// KyberPreKeyStore stores Kyber pre-keys (for PQXDH).
type KyberPreKeyStore interface {
	// LoadKyberPreKey retrieves a Kyber pre-key by ID.
	LoadKyberPreKey(id uint32) (*keys.KyberPreKey, error)
	// StoreKyberPreKey stores a Kyber pre-key.
	StoreKyberPreKey(id uint32, kyberPreKey *keys.KyberPreKey) error
	// ContainsKyberPreKey checks if a Kyber pre-key exists.
	ContainsKyberPreKey(id uint32) bool
	// RemoveKyberPreKey deletes a Kyber pre-key.
	RemoveKyberPreKey(id uint32) error
}

// SessionRecord is an opaque container for session persistence.
// Data holds a serialized session record (for example, the output of
// (*session.Record).Serialize()).
type SessionRecord struct {
	Data []byte
}

// SessionStore stores session records by address.
type SessionStore interface {
	// LoadSession retrieves a session record for the given address.
	// It returns a nil record if no session exists.
	LoadSession(address Address) (*SessionRecord, error)
	// StoreSession stores a session record for the given address.
	StoreSession(address Address, record *SessionRecord) error
	// ContainsSession checks if a session exists for the given address.
	ContainsSession(address Address) bool
	// DeleteSession removes the session for the given address.
	DeleteSession(address Address) error
	// DeleteAllSessions removes all sessions for a given user (name).
	DeleteAllSessions(name string) error
	// EnforceSessionLimit trims stored sessions for the address' name per store policy.
	EnforceSessionLimit(address Address) error
}

// SenderKeyName identifies a Sender Key state for a (group + sender) tuple.
type SenderKeyName struct {
	Group  string
	Sender Address
}

// SenderKeyRecord is an opaque container for sender key persistence.
// Data holds a serialized sender key record (for example, the output of
// (*senderkeys.Record).Serialize()).
type SenderKeyRecord struct {
	Data []byte
}

// SenderKeyStore stores sender key records by SenderKeyName.
type SenderKeyStore interface {
	// LoadSenderKey retrieves a sender key record.
	LoadSenderKey(name SenderKeyName) (*SenderKeyRecord, error)
	// StoreSenderKey stores a sender key record.
	StoreSenderKey(name SenderKeyName, record *SenderKeyRecord) error
	// ContainsSenderKey checks if a sender key record exists.
	ContainsSenderKey(name SenderKeyName) bool
	// DeleteSenderKey removes a sender key record.
	DeleteSenderKey(name SenderKeyName) error
	// DeleteAllSenderKeys removes all sender key records for a group.
	DeleteAllSenderKeys(group string) error
}

// SesameRecord is an opaque container for Sesame (multi-device roster) persistence.
// Data holds a serialized Sesame state (for example, the output of (*sesame.State).Serialize()).
type SesameRecord struct {
	Data []byte
}

// SesameStore stores the Sesame device roster state for the local device.
type SesameStore interface {
	// LoadSesameState retrieves the sesame state.
	LoadSesameState() (*SesameRecord, error)
	// StoreSesameState stores the sesame state.
	StoreSesameState(record *SesameRecord) error
	// DeleteSesameState removes the sesame state.
	DeleteSesameState() error
}

// ProtocolStore combines all store interfaces.
// This is the main interface that applications need to implement to provide storage.
type ProtocolStore interface {
	IdentityKeyStore
	PreKeyStore
	SignedPreKeyStore
	KyberPreKeyStore
	SessionStore
	SenderKeyStore
	SesameStore
}
