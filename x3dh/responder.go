package x3dh

import (
	"errors"
	"fmt"

	signalcrypto "github.com/deicod/signal/crypto"
	"github.com/deicod/signal/keys"
	"github.com/deicod/signal/store"
)

// Responder performs the responder side of the X3DH handshake.
type Responder struct {
	identityKey  *keys.IdentityKeyPair
	signedPreKey *keys.SignedPreKey
	preKeyStore  store.PreKeyStore
}

// NewResponder constructs a responder with identity, signed pre-key, and pre-key store.
func NewResponder(identityKey *keys.IdentityKeyPair, signedPreKey *keys.SignedPreKey, preKeyStore store.PreKeyStore) *Responder {
	return &Responder{
		identityKey:  identityKey,
		signedPreKey: signedPreKey,
		preKeyStore:  preKeyStore,
	}
}

// ProcessInitialMessage derives the shared secret from the initiator's message and removes one-time pre-keys if used.
func (r *Responder) ProcessInitialMessage(msg *Message) (*Result, error) {
	if r == nil || r.identityKey == nil || r.signedPreKey == nil {
		return nil, errors.New("responder: missing keys")
	}
	if msg == nil {
		return nil, errors.New("responder: message is nil")
	}
	if msg.SignedPreKeyID != r.signedPreKey.ID {
		return nil, fmt.Errorf("responder: signed pre-key id mismatch")
	}

	// DH1 = DH(SPKb, IKa)
	dh1, err := signalcrypto.DH(r.signedPreKey.KeyPair.PrivateKey, msg.IdentityKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("responder: dh1: %w", err)
	}
	// DH2 = DH(IKb, EKa)
	dh2, err := signalcrypto.DH(r.identityKey.PrivateKey, msg.EphemeralKey)
	if err != nil {
		return nil, fmt.Errorf("responder: dh2: %w", err)
	}
	// DH3 = DH(SPKb, EKa)
	dh3, err := signalcrypto.DH(r.signedPreKey.KeyPair.PrivateKey, msg.EphemeralKey)
	if err != nil {
		return nil, fmt.Errorf("responder: dh3: %w", err)
	}

	ikm := append(append(dh1[:], dh2[:]...), dh3[:]...)

	if msg.PreKeyID != nil {
		pre, err := r.preKeyStore.LoadPreKey(*msg.PreKeyID)
		if err != nil {
			return nil, fmt.Errorf("responder: load pre-key: %w", err)
		}
		if pre == nil || pre.KeyPair == nil {
			return nil, fmt.Errorf("responder: missing pre-key %d", *msg.PreKeyID)
		}
		dh4, err := signalcrypto.DH(pre.KeyPair.PrivateKey, msg.EphemeralKey)
		if err != nil {
			return nil, fmt.Errorf("responder: dh4: %w", err)
		}
		ikm = append(ikm, dh4[:]...)
		_ = r.preKeyStore.RemovePreKey(*msg.PreKeyID)
	}

	secretBytes, err := signalcrypto.HKDF(ikm, nil, infoString, 32)
	if err != nil {
		return nil, fmt.Errorf("responder: hkdf: %w", err)
	}
	var shared [32]byte
	copy(shared[:], secretBytes)

	return &Result{
		SharedSecret:   shared,
		AssociatedData: AssociatedData(msg.IdentityKey, r.identityKey.PublicKey),
		RemoteIdentity: msg.IdentityKey,
		InitialMessage: *msg,
	}, nil
}
