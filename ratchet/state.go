package ratchet

import (
	"errors"
	"fmt"

	signalcrypto "github.com/deicod/signal/crypto"
	"github.com/deicod/signal/x3dh"
)

// State holds Double Ratchet state.
type State struct {
	// DH Ratchet
	DHs *signalcrypto.KeyPair // Our current DH key pair
	DHr *[32]byte             // Their current DH public key

	// Root key
	RK [32]byte

	// Chain keys
	CKs [32]byte // Sending chain key
	CKr [32]byte // Receiving chain key

	// Message numbers
	Ns uint32 // Send message number
	Nr uint32 // Receive message number
	PN uint32 // Previous chain length

	// Skipped message keys
	MKSkipped map[SkippedKey][32]byte
}

// SkippedKey indexes skipped message keys.
type SkippedKey struct {
	PublicKey [32]byte
	N         uint32
}

// InitializeState constructs a Double Ratchet state from X3DH output.
func InitializeState(x3 *x3dh.Result, isInitiator bool) (*State, error) {
	if x3 == nil {
		return nil, errors.New("ratchet: x3dh result required")
	}
	s := &State{
		MKSkipped: make(map[SkippedKey][32]byte),
	}

	// Derive initial root and chain keys from shared secret.
	// For now, split into RK and CKs using HKDF with distinct info labels.
	rk, cks, err := deriveInitialKeys(x3.SharedSecret[:], isInitiator)
	if err != nil {
		return nil, err
	}
	s.RK = rk
	if isInitiator {
		s.CKs = cks
	} else {
		s.CKr = cks
	}

	// Set DH keys: initiator uses its ephemeral as DHs; responder has DHr only.
	if isInitiator {
		// Initiator sends first; DHs is its ephemeral, DHr is nil until reply.
		dh := x3.InitialMessage.EphemeralKey
		s.DHs = &signalcrypto.KeyPair{PublicKey: dh}
	} else {
		// Responder has received initiator's DH (in message header).
		dh := x3.InitialMessage.EphemeralKey
		s.DHr = &dh
	}

	return s, nil
}

// Clone returns a deep copy of the state suitable for atomic updates.
func (s *State) Clone() *State {
	if s == nil {
		return nil
	}
	clone := *s
	if s.DHs != nil {
		kp := *s.DHs
		clone.DHs = &kp
	}
	if s.DHr != nil {
		dhr := *s.DHr
		clone.DHr = &dhr
	}
	clone.MKSkipped = make(map[SkippedKey][32]byte, len(s.MKSkipped))
	for k, v := range s.MKSkipped {
		clone.MKSkipped[k] = v
	}
	return &clone
}

// RatchetOnSend performs a DH ratchet before sending if DHr is set (i.e., after receiving a new DH).
func (s *State) RatchetOnSend() error {
	if s.DHr == nil || s.DHs == nil {
		// No pending remote DH; nothing to ratchet.
		return nil
	}
	return s.DHRatchet(*s.DHr)
}

func deriveInitialKeys(shared []byte, _ bool) (root [32]byte, ck [32]byte, err error) {
	if len(shared) != 32 {
		return root, ck, fmt.Errorf("ratchet: shared secret must be 32 bytes, got %d", len(shared))
	}
	infoRK := []byte("DoubleRatchetRoot")
	infoCK := []byte("DoubleRatchetChain")

	rkBytes, err := signalcrypto.HKDF(shared, nil, infoRK, 32)
	if err != nil {
		return root, ck, fmt.Errorf("ratchet: hkdf root: %w", err)
	}
	ckBytes, err := signalcrypto.HKDF(shared, nil, infoCK, 32)
	if err != nil {
		return root, ck, fmt.Errorf("ratchet: hkdf chain: %w", err)
	}
	copy(root[:], rkBytes)
	copy(ck[:], ckBytes)
	zeroBytes(rkBytes)
	zeroBytes(ckBytes)
	return root, ck, nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
