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

// GenerateIdentityKeyPair creates a new identity key pair (Curve25519).
// Identity keys are long-lived and identify a user/device.
func GenerateIdentityKeyPair() (*IdentityKeyPair, error) {
	return keys.GenerateIdentityKeyPair()
}

// GeneratePreKey creates a one-time pre-key (Curve25519) with the given id.
// One-time pre-keys are used to establish new sessions and are consumed upon use.
func GeneratePreKey(id uint32) (*PreKey, error) {
	return keys.GeneratePreKey(id)
}

// GeneratePreKeys creates a sequence of pre-keys starting at startID.
// This is a helper for batch generation of one-time pre-keys.
func GeneratePreKeys(startID uint32, count int) ([]*PreKey, error) {
	return keys.GeneratePreKeys(startID, count)
}

// GenerateSignedPreKey creates a signed pre-key (Curve25519) using identityKey for the signature.
// Signed pre-keys are rotated periodically (e.g., weekly) and signed by the identity key to prevent tampering.
func GenerateSignedPreKey(identityKey *IdentityKeyPair, id uint32) (*SignedPreKey, error) {
	return keys.GenerateSignedPreKey(identityKey, id)
}

// GenerateKyberPreKey creates a signed Kyber pre-key using identityKey for the signature.
// Kyber pre-keys provide post-quantum resistance for the initial key exchange (PQXDH).
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
