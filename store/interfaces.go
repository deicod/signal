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

// KyberPreKeyStore stores Kyber pre-keys.
type KyberPreKeyStore interface {
	LoadKyberPreKey(id uint32) (*keys.KyberPreKey, error)
	StoreKyberPreKey(id uint32, kyberPreKey *keys.KyberPreKey) error
	ContainsKyberPreKey(id uint32) bool
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
	LoadSession(address Address) (*SessionRecord, error)
	StoreSession(address Address, record *SessionRecord) error
	ContainsSession(address Address) bool
	DeleteSession(address Address) error
	DeleteAllSessions(name string) error
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
	LoadSenderKey(name SenderKeyName) (*SenderKeyRecord, error)
	StoreSenderKey(name SenderKeyName, record *SenderKeyRecord) error
	ContainsSenderKey(name SenderKeyName) bool
	DeleteSenderKey(name SenderKeyName) error
	DeleteAllSenderKeys(group string) error
}

// SesameRecord is an opaque container for Sesame (multi-device roster) persistence.
// Data holds a serialized Sesame state (for example, the output of (*sesame.State).Serialize()).
type SesameRecord struct {
	Data []byte
}

// SesameStore stores the Sesame device roster state for the local device.
type SesameStore interface {
	LoadSesameState() (*SesameRecord, error)
	StoreSesameState(record *SesameRecord) error
	DeleteSesameState() error
}

// ProtocolStore combines all store interfaces.
type ProtocolStore interface {
	IdentityKeyStore
	PreKeyStore
	SignedPreKeyStore
	KyberPreKeyStore
	SessionStore
	SenderKeyStore
	SesameStore
}
