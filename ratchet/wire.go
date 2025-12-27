package ratchet

import (
	"errors"
	"fmt"
	"math"

	signalerrors "github.com/deicod/signal/errors"
)

// NextSendingMessageKey advances the sending chain and returns the header and message key.
func (s *State) NextSendingMessageKey() (Header, [32]byte, error) {
	if s == nil {
		return Header{}, [32]byte{}, errors.New("encrypt: state is nil")
	}
	if s.DHs == nil {
		return Header{}, [32]byte{}, fmt.Errorf("encrypt: missing sending DH key")
	}
	if s.CKs == ([32]byte{}) {
		return Header{}, [32]byte{}, fmt.Errorf("encrypt: missing sending chain key")
	}
	if s.Ns == math.MaxUint32 {
		return Header{}, [32]byte{}, fmt.Errorf("%w: send counter overflow", signalerrors.ErrCounterOverflow)
	}

	header := Header{
		DH: s.DHs.PublicKey,
		PN: s.PN,
		N:  s.Ns,
	}

	newCKs, mk := KDFChain(s.CKs)
	s.CKs = newCKs
	s.Ns++

	return header, mk, nil
}

// AdvanceForHeader advances the receiver state for the given header and returns the message key.
// Callers should apply this on a cloned state and only commit on successful MAC/decryption.
func (s *State) AdvanceForHeader(header *Header) (*[32]byte, error) {
	if header == nil {
		return nil, fmt.Errorf("decrypt: header is nil")
	}
	if s == nil {
		return nil, fmt.Errorf("decrypt: state is nil")
	}

	if key, ok := skippedKeyForHeader(header); ok {
		if mk, ok := s.MKSkipped[key]; ok {
			delete(s.MKSkipped, key)
			return &mk, nil
		}
	}

	if s.DHr != nil && header.DH == *s.DHr && header.N < s.Nr {
		return nil, fmt.Errorf("%w: message already processed", signalerrors.ErrDuplicateMessage)
	}

	if s.DHr != nil && header.DH != *s.DHr {
		if _, ok := s.SeenDH[header.DH]; ok {
			return nil, fmt.Errorf("%w: message for previous ratchet key", signalerrors.ErrDuplicateMessage)
		}
	}

	if s.DHr == nil || *s.DHr != header.DH {
		if err := s.skipMessageKeys(header.PN); err != nil {
			return nil, err
		}
		if err := s.DHRatchet(header.DH); err != nil {
			return nil, err
		}
	}

	if err := s.skipMessageKeys(header.N); err != nil {
		return nil, err
	}

	if s.CKr == ([32]byte{}) {
		return nil, fmt.Errorf("decrypt: missing receiving chain key")
	}
	if s.Nr == math.MaxUint32 {
		return nil, fmt.Errorf("%w: receive counter overflow", signalerrors.ErrCounterOverflow)
	}

	newCKr, mk := KDFChain(s.CKr)
	s.CKr = newCKr
	s.Nr++

	return &mk, nil
}
