package x3dh

import (
	"errors"
	"fmt"

	signalcrypto "github.com/deicod/signal/crypto"
	signalerrors "github.com/deicod/signal/errors"
	"github.com/deicod/signal/keys"
	"github.com/deicod/signal/store"
)

// Responder performs the responder side of the X3DH handshake.
type Responder struct {
	identityKey  *keys.IdentityKeyPair
	signedPreKey *keys.SignedPreKey
	preKeyStore  store.PreKeyStore
	kyberStore   store.KyberPreKeyStore
}

// NewResponder constructs a responder with identity, signed pre-key, and pre-key stores.
func NewResponder(identityKey *keys.IdentityKeyPair, signedPreKey *keys.SignedPreKey, preKeyStore store.PreKeyStore, kyberStore store.KyberPreKeyStore) *Responder {
	return &Responder{
		identityKey:  identityKey,
		signedPreKey: signedPreKey,
		preKeyStore:  preKeyStore,
		kyberStore:   kyberStore,
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
			return nil, fmt.Errorf("%w: one-time pre-key %d", signalerrors.ErrPreKeyNotFound, *msg.PreKeyID)
		}
		dh4, err := signalcrypto.DH(pre.KeyPair.PrivateKey, msg.EphemeralKey)
		if err != nil {
			return nil, fmt.Errorf("responder: dh4: %w", err)
		}
		ikm = append(ikm, dh4[:]...)
		if err := r.preKeyStore.RemovePreKey(*msg.PreKeyID); err != nil {
			return nil, fmt.Errorf("responder: remove pre-key: %w", err)
		}
	}

	var shared [32]byte
	var initialChain *[32]byte

	if msg.KyberPreKeyID != nil || len(msg.KyberCiphertext) > 0 {
		if msg.KyberPreKeyID == nil || len(msg.KyberCiphertext) == 0 {
			return nil, fmt.Errorf("%w: kyber id/ciphertext mismatch", signalerrors.ErrInvalidMessage)
		}
		if r.kyberStore == nil {
			return nil, fmt.Errorf("responder: kyber pre-key store required")
		}
		kyberPreKey, err := r.kyberStore.LoadKyberPreKey(*msg.KyberPreKeyID)
		if err != nil {
			return nil, fmt.Errorf("responder: load kyber pre-key: %w", err)
		}
		if kyberPreKey == nil || kyberPreKey.KeyPair == nil {
			return nil, fmt.Errorf("%w: kyber pre-key %d", signalerrors.ErrPreKeyNotFound, *msg.KyberPreKeyID)
		}
		kyberSS, err := signalcrypto.Kyber1024Decapsulate(kyberPreKey.KeyPair.PrivateKey, msg.KyberCiphertext)
		if err != nil {
			return nil, fmt.Errorf("responder: kyber decapsulate: %w", err)
		}
		ikmPQ := append(append([]byte{}, discontinuity...), ikm...)
		ikmPQ = append(ikmPQ, kyberSS...)
		root, chain, err := derivePQSecret(ikmPQ)
		if err != nil {
			return nil, fmt.Errorf("responder: hkdf: %w", err)
		}
		shared = root
		initialChain = &chain
		signalcrypto.ZeroBytes(kyberSS)
		signalcrypto.ZeroBytes(ikmPQ)
	} else {
		root, err := deriveLegacySecret(ikm)
		if err != nil {
			return nil, fmt.Errorf("responder: hkdf: %w", err)
		}
		shared = root
	}
	signalcrypto.ZeroBytes(ikm)

	return &Result{
		SharedSecret:    shared,
		InitialChainKey: initialChain,
		AssociatedData:  AssociatedData(msg.IdentityKey, r.identityKey.PublicKey),
		RemoteIdentity:  msg.IdentityKey,
		InitialMessage:  *msg,
		LocalRatchetKey: r.signedPreKey.KeyPair,
	}, nil
}
