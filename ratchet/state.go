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
	if x3.SharedSecret == ([32]byte{}) {
		return nil, errors.New("ratchet: shared secret must be set")
	}

	state := &State{
		RK:        x3.SharedSecret,
		MKSkipped: make(map[SkippedKey][32]byte),
	}

	if isInitiator {
		var err error
		if x3.LocalEphemeral != nil {
			kp := *x3.LocalEphemeral
			state.DHs = &kp
		} else {
			state.DHs, err = signalcrypto.GenerateKeyPair()
			if err != nil {
				return nil, fmt.Errorf("ratchet: generate initiator dh: %w", err)
			}
		}
		if x3.RemoteRatchetKey == nil {
			return nil, errors.New("ratchet: initiator missing remote ratchet key")
		}
		state.DHr = x3.RemoteRatchetKey

		dhOut, err := signalcrypto.DH(state.DHs.PrivateKey, *state.DHr)
		if err != nil {
			return nil, fmt.Errorf("ratchet: initial dh (initiator): %w", err)
		}
		newRK, cks, err := KDFRoot(state.RK, dhOut)
		if err != nil {
			return nil, err
		}
		state.RK = newRK
		state.CKs = cks
	} else {
		remoteDH := x3.InitialMessage.EphemeralKey
		state.DHr = &remoteDH

		if x3.LocalRatchetKey != nil {
			kp := *x3.LocalRatchetKey
			state.DHs = &kp
		} else {
			dh, err := signalcrypto.GenerateKeyPair()
			if err != nil {
				return nil, fmt.Errorf("ratchet: generate responder dh: %w", err)
			}
			state.DHs = dh
		}

		// First derive receiving chain from initial DH.
		dhRecv, err := signalcrypto.DH(state.DHs.PrivateKey, remoteDH)
		if err != nil {
			return nil, fmt.Errorf("ratchet: initial dh (responder): %w", err)
		}
		newRK, ckr, err := KDFRoot(state.RK, dhRecv)
		if err != nil {
			return nil, err
		}
		state.RK = newRK
		state.CKr = ckr

		// Prepare a fresh DHs for sending chain.
		newDH, err := signalcrypto.GenerateKeyPair()
		if err != nil {
			return nil, fmt.Errorf("ratchet: generate send dh: %w", err)
		}
		dhSend, err := signalcrypto.DH(newDH.PrivateKey, remoteDH)
		if err != nil {
			return nil, fmt.Errorf("ratchet: dh send setup: %w", err)
		}
		newRK, cks, err := KDFRoot(state.RK, dhSend)
		if err != nil {
			return nil, err
		}
		state.RK = newRK
		state.CKs = cks
		state.DHs = newDH
	}

	return state, nil
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
		return nil
	}
	return s.DHRatchet(*s.DHr)
}
