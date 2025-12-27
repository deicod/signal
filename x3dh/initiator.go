package x3dh

import (
	"errors"
	"fmt"

	signalcrypto "github.com/deicod/signal/crypto"
	"github.com/deicod/signal/keys"
)

// Initiator performs the initiator side of the X3DH handshake.
type Initiator struct {
	identityKey *keys.IdentityKeyPair
}

// NewInitiator constructs an initiator with the given identity key pair.
func NewInitiator(identityKey *keys.IdentityKeyPair) *Initiator {
	return &Initiator{identityKey: identityKey}
}

// ProcessPreKeyBundle derives the shared secret and initial message for the responder.
func (x *Initiator) ProcessPreKeyBundle(bundle *keys.PreKeyBundle) (*Result, error) {
	if x == nil || x.identityKey == nil {
		return nil, errors.New("initiator: identity key required")
	}
	if bundle == nil {
		return nil, errors.New("initiator: bundle is nil")
	}
	if err := bundle.Validate(); err != nil {
		return nil, fmt.Errorf("initiator: invalid bundle: %w", err)
	}

	ephemeral, err := signalcrypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("initiator: generate ephemeral: %w", err)
	}

	// DH1 = DH(IKa, SPKb)
	dh1, err := signalcrypto.DH(x.identityKey.PrivateKey, bundle.SignedPreKeyPublic)
	if err != nil {
		return nil, fmt.Errorf("initiator: dh1: %w", err)
	}
	// DH2 = DH(EKa, IKb)
	dh2, err := signalcrypto.DH(ephemeral.PrivateKey, bundle.IdentityKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("initiator: dh2: %w", err)
	}
	// DH3 = DH(EKa, SPKb)
	dh3, err := signalcrypto.DH(ephemeral.PrivateKey, bundle.SignedPreKeyPublic)
	if err != nil {
		return nil, fmt.Errorf("initiator: dh3: %w", err)
	}

	ikm := append(append(dh1[:], dh2[:]...), dh3[:]...)
	if bundle.PreKeyPublic != nil {
		dh4, err := signalcrypto.DH(ephemeral.PrivateKey, *bundle.PreKeyPublic)
		if err != nil {
			return nil, fmt.Errorf("initiator: dh4: %w", err)
		}
		ikm = append(ikm, dh4[:]...)
	}

	var shared [32]byte
	var initialChain *[32]byte
	var kyberCiphertext []byte

	if bundle.KyberPreKeyID != nil {
		kyberSS, kyberCT, err := signalcrypto.Kyber1024Encapsulate(bundle.KyberPreKeyPublic)
		if err != nil {
			return nil, fmt.Errorf("initiator: kyber encapsulate: %w", err)
		}
		ikmPQ := append(append([]byte{}, discontinuity...), ikm...)
		ikmPQ = append(ikmPQ, kyberSS...)
		root, chain, err := derivePQSecret(ikmPQ)
		if err != nil {
			return nil, fmt.Errorf("initiator: hkdf: %w", err)
		}
		shared = root
		initialChain = &chain
		kyberCiphertext = kyberCT
		signalcrypto.ZeroBytes(kyberSS)
		signalcrypto.ZeroBytes(ikmPQ)
	} else {
		root, err := deriveLegacySecret(ikm)
		if err != nil {
			return nil, fmt.Errorf("initiator: hkdf: %w", err)
		}
		shared = root
	}
	signalcrypto.ZeroBytes(ikm)

	msg := Message{
		IdentityKey:    x.identityKey.PublicKey,
		EphemeralKey:   ephemeral.PublicKey,
		PreKeyID:       bundle.PreKeyID,
		SignedPreKeyID: bundle.SignedPreKeyID,
		KyberPreKeyID:  bundle.KyberPreKeyID,
		KyberCiphertext: kyberCiphertext,
	}

	return &Result{
		SharedSecret:     shared,
		InitialChainKey:  initialChain,
		AssociatedData:   AssociatedData(x.identityKey.PublicKey, bundle.IdentityKey),
		RemoteIdentity:   bundle.IdentityKey,
		InitialMessage:   msg,
		LocalEphemeral:   ephemeral,
		RemoteRatchetKey: &bundle.SignedPreKeyPublic,
	}, nil
}
