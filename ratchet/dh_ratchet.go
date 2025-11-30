package ratchet

import (
	"fmt"

	signalcrypto "github.com/deicod/signal/crypto"
)

// KDFRoot derives a new root key and chain key from the current root key and DH output.
// Uses HKDF with distinct info label.
func KDFRoot(rootKey [32]byte, dhOutput [32]byte) (newRootKey, chainKey [32]byte, err error) {
	info := []byte("DoubleRatchetRootKDF")
	okm, err := signalcrypto.HKDF(append(rootKey[:], dhOutput[:]...), nil, info, 64)
	if err != nil {
		return newRootKey, chainKey, fmt.Errorf("kdf root: %w", err)
	}
	copy(newRootKey[:], okm[:32])
	copy(chainKey[:], okm[32:64])
	return newRootKey, chainKey, nil
}

// DHRatchet performs a DH ratchet step when a new remote DH public key arrives.
func (s *State) DHRatchet(theirPublicKey [32]byte) error {
	if s.DHs == nil {
		return fmt.Errorf("dh ratchet: missing local dh key")
	}
	// Update PN and reset message numbers.
	s.PN = s.Ns
	s.Ns = 0
	s.Nr = 0

	// Perform DH with new remote key to derive receiving chain key.
	dhOut, err := signalcrypto.DH(s.DHs.PrivateKey, theirPublicKey)
	if err != nil {
		return fmt.Errorf("dh ratchet: dh1: %w", err)
	}
	newRoot, newCKr, err := KDFRoot(s.RK, dhOut)
	if err != nil {
		return err
	}
	s.RK = newRoot
	s.CKr = newCKr

	// Step our DH and derive sending chain key.
	newDH, err := signalcrypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("dh ratchet: generate local dh: %w", err)
	}
	s.DHs = newDH
	dhOutSend, err := signalcrypto.DH(s.DHs.PrivateKey, theirPublicKey)
	if err != nil {
		return fmt.Errorf("dh ratchet: dh2: %w", err)
	}
	newRoot, newCKs, err := KDFRoot(s.RK, dhOutSend)
	if err != nil {
		return err
	}
	s.RK = newRoot
	s.CKs = newCKs
	s.DHr = &theirPublicKey
	s.cleanupSkippedKeys(*s.DHr)
	return nil
}
