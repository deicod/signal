package signal

import (
	"fmt"

	signalerrors "github.com/deicod/signal/errors"
)

// GenerateAndStorePreKey creates a one-time pre-key and stores it in s.
func GenerateAndStorePreKey(s ProtocolStore, id uint32) (*PreKey, error) {
	if s == nil {
		return nil, fmt.Errorf("store is nil")
	}
	pk, err := GeneratePreKey(id)
	if err != nil {
		return nil, err
	}
	if err := s.StorePreKey(pk.ID, pk); err != nil {
		return nil, fmt.Errorf("store pre-key: %w", err)
	}
	return pk, nil
}

// GenerateAndStoreSignedPreKey creates a signed pre-key using the store's identity key pair and stores it in s.
func GenerateAndStoreSignedPreKey(s ProtocolStore, id uint32) (*SignedPreKey, error) {
	if s == nil {
		return nil, fmt.Errorf("store is nil")
	}
	identity, err := s.GetIdentityKeyPair()
	if err != nil {
		return nil, fmt.Errorf("load identity: %w", err)
	}
	spk, err := GenerateSignedPreKey(identity, id)
	if err != nil {
		return nil, err
	}
	if err := s.StoreSignedPreKey(spk.ID, spk); err != nil {
		return nil, fmt.Errorf("store signed pre-key: %w", err)
	}
	return spk, nil
}

// GenerateAndStoreKyberPreKey creates a signed Kyber pre-key using the store's identity key pair and stores it in s.
func GenerateAndStoreKyberPreKey(s ProtocolStore, id uint32) (*KyberPreKey, error) {
	if s == nil {
		return nil, fmt.Errorf("store is nil")
	}
	identity, err := s.GetIdentityKeyPair()
	if err != nil {
		return nil, fmt.Errorf("load identity: %w", err)
	}
	kpk, err := GenerateKyberPreKey(identity, id)
	if err != nil {
		return nil, err
	}
	if err := s.StoreKyberPreKey(kpk.ID, kpk); err != nil {
		return nil, fmt.Errorf("store kyber pre-key: %w", err)
	}
	return kpk, nil
}

// BuildPreKeyBundle constructs a pre-key bundle for publishing from keys stored in s.
func BuildPreKeyBundle(s ProtocolStore, deviceID uint32, preKeyID *uint32, signedPreKeyID uint32, kyberPreKeyID *uint32) (*PreKeyBundle, error) {
	if s == nil {
		return nil, fmt.Errorf("store is nil")
	}
	registrationID, err := s.GetLocalRegistrationID()
	if err != nil {
		return nil, fmt.Errorf("load registration id: %w", err)
	}
	identity, err := s.GetIdentityKeyPair()
	if err != nil {
		return nil, fmt.Errorf("load identity: %w", err)
	}
	signed, err := s.LoadSignedPreKey(signedPreKeyID)
	if err != nil {
		return nil, fmt.Errorf("load signed pre-key: %w", err)
	}
	if signed == nil {
		return nil, fmt.Errorf("%w: signed pre-key %d", signalerrors.ErrPreKeyNotFound, signedPreKeyID)
	}

	var kyber *KyberPreKey
	if kyberPreKeyID != nil {
		kyber, err = s.LoadKyberPreKey(*kyberPreKeyID)
		if err != nil {
			return nil, fmt.Errorf("load kyber pre-key: %w", err)
		}
		if kyber == nil {
			return nil, fmt.Errorf("%w: kyber pre-key %d", signalerrors.ErrPreKeyNotFound, *kyberPreKeyID)
		}
	}

	var preKey *PreKey
	if preKeyID != nil {
		preKey, err = s.LoadPreKey(*preKeyID)
		if err != nil {
			return nil, fmt.Errorf("load pre-key: %w", err)
		}
		if preKey == nil {
			return nil, fmt.Errorf("%w: pre-key %d", signalerrors.ErrPreKeyNotFound, *preKeyID)
		}
	}

	bundle, err := NewPreKeyBundleWithKyber(registrationID, deviceID, preKey, signed, kyber, identity.PublicKey)
	if err != nil {
		return nil, err
	}
	if err := bundle.Validate(); err != nil {
		return nil, err
	}
	return bundle, nil
}
