package signal

import "github.com/deicod/signal/keys"

// IdentityKey identifies a peer for DH and signature verification.
type IdentityKey = keys.IdentityKey

// IdentityKeyPair is the local identity key pair.
type IdentityKeyPair = keys.IdentityKeyPair

// PreKey is a one-time pre-key.
type PreKey = keys.PreKey

// SignedPreKey is a long-lived signed pre-key.
type SignedPreKey = keys.SignedPreKey

// KyberPreKey is a signed post-quantum pre-key.
type KyberPreKey = keys.KyberPreKey

// GenerateIdentityKeyPair creates a new identity key pair.
func GenerateIdentityKeyPair() (*IdentityKeyPair, error) {
	return keys.GenerateIdentityKeyPair()
}

// GeneratePreKey creates a one-time pre-key with the given id.
func GeneratePreKey(id uint32) (*PreKey, error) {
	return keys.GeneratePreKey(id)
}

// GeneratePreKeys creates a sequence of pre-keys starting at startID.
func GeneratePreKeys(startID uint32, count int) ([]*PreKey, error) {
	return keys.GeneratePreKeys(startID, count)
}

// GenerateSignedPreKey creates a signed pre-key using identityKey for the signature.
func GenerateSignedPreKey(identityKey *IdentityKeyPair, id uint32) (*SignedPreKey, error) {
	return keys.GenerateSignedPreKey(identityKey, id)
}

// GenerateKyberPreKey creates a signed Kyber pre-key using identityKey for the signature.
func GenerateKyberPreKey(identityKey *IdentityKeyPair, id uint32) (*KyberPreKey, error) {
	return keys.GenerateKyberPreKey(identityKey, id)
}

// NewPreKeyBundle builds a pre-key bundle with an optional one-time pre-key.
func NewPreKeyBundle(registrationID, deviceID uint32, preKey *PreKey, signedPreKey *SignedPreKey, identity IdentityKey) (*PreKeyBundle, error) {
	return keys.NewPreKeyBundle(registrationID, deviceID, preKey, signedPreKey, identity)
}

// NewPreKeyBundleWithKyber builds a pre-key bundle with an optional Kyber pre-key.
func NewPreKeyBundleWithKyber(registrationID, deviceID uint32, preKey *PreKey, signedPreKey *SignedPreKey, kyberPreKey *KyberPreKey, identity IdentityKey) (*PreKeyBundle, error) {
	return keys.NewPreKeyBundleWithKyber(registrationID, deviceID, preKey, signedPreKey, kyberPreKey, identity)
}
