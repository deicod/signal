package keys

import (
	"fmt"

	signalcrypto "github.com/deicod/signal/crypto"
	signalerrors "github.com/deicod/signal/errors"
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
	KyberPreKeyID         *uint32
	KyberPreKeyPublic     []byte
	KyberPreKeySignature  []byte
	IdentityKey           IdentityKey
}

// NewPreKeyBundle builds a bundle with an optional one-time pre-key (legacy, no Kyber).
func NewPreKeyBundle(registrationID, deviceID uint32, preKey *PreKey, signedPreKey *SignedPreKey, identity IdentityKey) (*PreKeyBundle, error) {
	return NewPreKeyBundleWithKyber(registrationID, deviceID, preKey, signedPreKey, nil, identity)
}

// NewPreKeyBundleWithKyber builds a bundle with optional one-time pre-key and Kyber pre-key.
func NewPreKeyBundleWithKyber(registrationID, deviceID uint32, preKey *PreKey, signedPreKey *SignedPreKey, kyberPreKey *KyberPreKey, identity IdentityKey) (*PreKeyBundle, error) {
	if signedPreKey == nil {
		return nil, fmt.Errorf("%w: signed pre-key required", signalerrors.ErrInvalidKey)
	}

	var preKeyID *uint32
	var preKeyPub *[32]byte
	if preKey != nil {
		preKeyID = &preKey.ID
		preKeyPub = &preKey.KeyPair.PublicKey
	}

	if signedPreKey.KeyPair == nil {
		return nil, fmt.Errorf("%w: signed pre-key missing keypair", signalerrors.ErrInvalidKey)
	}

	var kyberID *uint32
	var kyberPub []byte
	var kyberSig []byte
	if kyberPreKey != nil {
		if kyberPreKey.KeyPair == nil || len(kyberPreKey.KeyPair.PublicKey) == 0 {
			return nil, fmt.Errorf("%w: kyber pre-key missing public key", signalerrors.ErrInvalidKey)
		}
		if len(kyberPreKey.Signature) == 0 {
			return nil, fmt.Errorf("%w: kyber pre-key missing signature", signalerrors.ErrInvalidSignature)
		}
		kyberID = &kyberPreKey.ID
		kyberPub = append([]byte(nil), kyberPreKey.KeyPair.PublicKey...)
		kyberSig = append([]byte(nil), kyberPreKey.Signature...)
	}

	return &PreKeyBundle{
		RegistrationID:        registrationID,
		DeviceID:              deviceID,
		PreKeyID:              preKeyID,
		PreKeyPublic:          preKeyPub,
		SignedPreKeyID:        signedPreKey.ID,
		SignedPreKeyPublic:    signedPreKey.KeyPair.PublicKey,
		SignedPreKeySignature: signedPreKey.Signature,
		KyberPreKeyID:         kyberID,
		KyberPreKeyPublic:     kyberPub,
		KyberPreKeySignature:  kyberSig,
		IdentityKey:           identity,
	}, nil
}

// Validate checks signatures and required fields.
func (b *PreKeyBundle) Validate() error {
	if b == nil {
		return fmt.Errorf("%w: bundle is nil", signalerrors.ErrInvalidMessage)
	}
	if len(b.SignedPreKeySignature) == 0 {
		return fmt.Errorf("%w: missing signed pre-key signature", signalerrors.ErrInvalidSignature)
	}
	if b.SignedPreKeyID == 0 {
		return fmt.Errorf("%w: signed pre-key id must be set", signalerrors.ErrInvalidKey)
	}

	// Verify signed pre-key signature.
	if !b.IdentityKey.Verify(SerializeWirePublicKey(b.SignedPreKeyPublic), b.SignedPreKeySignature) {
		return fmt.Errorf("%w: invalid signed pre-key signature", signalerrors.ErrInvalidSignature)
	}

	// If a one-time pre-key is present, ensure both ID and key are set.
	if (b.PreKeyID == nil) != (b.PreKeyPublic == nil) {
		return fmt.Errorf("%w: pre-key id/key mismatch", signalerrors.ErrInvalidMessage)
	}

	if (b.KyberPreKeyID == nil) != (len(b.KyberPreKeyPublic) == 0) {
		return fmt.Errorf("%w: kyber pre-key id/key mismatch", signalerrors.ErrInvalidMessage)
	}
	if (b.KyberPreKeyID == nil) != (len(b.KyberPreKeySignature) == 0) {
		return fmt.Errorf("%w: kyber pre-key id/signature mismatch", signalerrors.ErrInvalidMessage)
	}
	if b.KyberPreKeyID != nil {
		if *b.KyberPreKeyID == 0 {
			return fmt.Errorf("%w: kyber pre-key id must be set", signalerrors.ErrInvalidKey)
		}
		if !signalcrypto.IsKyber1024PublicKey(b.KyberPreKeyPublic) {
			return fmt.Errorf("%w: kyber pre-key invalid length", signalerrors.ErrInvalidKey)
		}
		if !b.IdentityKey.Verify(b.KyberPreKeyPublic, b.KyberPreKeySignature) {
			return fmt.Errorf("%w: invalid kyber pre-key signature", signalerrors.ErrInvalidSignature)
		}
	}

	return nil
}
