package keys

import (
	"errors"
	"fmt"
)

// PreKeyBundle is published to the server for clients to fetch.
type PreKeyBundle struct {
	RegistrationID        uint32
	DeviceID              uint32
	PreKeyID              *uint32   // Optional
	PreKeyPublic          *[32]byte // Optional
	SignedPreKeyID        uint32
	SignedPreKeyPublic    [32]byte
	SignedPreKeySignature []byte
	IdentityKey           IdentityKey
}

// NewPreKeyBundle builds a bundle with optional one-time pre-key.
func NewPreKeyBundle(registrationID, deviceID uint32, preKey *PreKey, signedPreKey *SignedPreKey, identity IdentityKey) (*PreKeyBundle, error) {
	if signedPreKey == nil {
		return nil, errors.New("signed pre-key required")
	}

	var preKeyID *uint32
	var preKeyPub *[32]byte
	if preKey != nil {
		preKeyID = &preKey.ID
		preKeyPub = &preKey.KeyPair.PublicKey
	}

	if signedPreKey.KeyPair == nil {
		return nil, errors.New("signed pre-key missing keypair")
	}

	return &PreKeyBundle{
		RegistrationID:        registrationID,
		DeviceID:              deviceID,
		PreKeyID:              preKeyID,
		PreKeyPublic:          preKeyPub,
		SignedPreKeyID:        signedPreKey.ID,
		SignedPreKeyPublic:    signedPreKey.KeyPair.PublicKey,
		SignedPreKeySignature: signedPreKey.Signature,
		IdentityKey:           identity,
	}, nil
}

// Validate checks signatures and required fields.
func (b *PreKeyBundle) Validate() error {
	if b == nil {
		return errors.New("bundle is nil")
	}
	if len(b.SignedPreKeySignature) == 0 {
		return errors.New("missing signed pre-key signature")
	}
	if b.SignedPreKeyID == 0 {
		return errors.New("signed pre-key id must be set")
	}

	// Verify signed pre-key signature.
	if !b.IdentityKey.Verify(b.SignedPreKeyPublic[:], b.SignedPreKeySignature) {
		return fmt.Errorf("invalid signed pre-key signature")
	}

	// If a one-time pre-key is present, ensure both ID and key are set.
	if (b.PreKeyID == nil) != (b.PreKeyPublic == nil) {
		return errors.New("pre-key id/key mismatch")
	}

	return nil
}
