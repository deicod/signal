package senderkeys

import (
	"fmt"
)

// DefaultMaxStates bounds archived sender key states to control memory usage.
const DefaultMaxStates = 5

const maxMessageKeysPerState = 2000
const distributionIDSize = 16

// Record tracks the current sender key state plus recently rotated prior states.
type Record struct {
	states    []*state
	maxStates int
}

// NewRecord creates an empty sender key record with the given state limit.
// If maxStates <= 0, DefaultMaxStates is used.
func NewRecord(maxStates int) *Record {
	if maxStates <= 0 {
		maxStates = DefaultMaxStates
	}
	return &Record{
		states:    nil,
		maxStates: maxStates,
	}
}

func (r *Record) isEmpty() bool {
	return r == nil || len(r.states) == 0
}

func (r *Record) current() (*state, error) {
	if r == nil || len(r.states) == 0 || r.states[0] == nil {
		return nil, fmt.Errorf("sender key record: missing state")
	}
	return r.states[0], nil
}

func (r *Record) state(distributionID [distributionIDSize]byte, keyID uint32) (*state, error) {
	if r == nil {
		return nil, fmt.Errorf("sender key record: nil record")
	}
	for _, s := range r.states {
		if s == nil {
			continue
		}
		if s.keyID == keyID && s.distributionID == distributionID {
			return s, nil
		}
	}
	return nil, fmt.Errorf("sender key record: missing state %d", keyID)
}

func (r *Record) setState(next *state) error {
	if r == nil {
		return fmt.Errorf("sender key record: nil record")
	}
	if next == nil {
		return fmt.Errorf("sender key record: state is nil")
	}

	filtered := r.states[:0]
	for _, s := range r.states {
		if s == nil {
			continue
		}
		if s.keyID == next.keyID && s.distributionID == next.distributionID {
			continue
		}
		filtered = append(filtered, s)
	}
	for i := len(filtered); i < len(r.states); i++ {
		r.states[i] = nil
	}
	r.states = filtered

	r.states = append([]*state{next}, r.states...)
	if len(r.states) > r.maxStates {
		r.states = r.states[:r.maxStates]
	}
	return nil
}

type state struct {
	messageVersion uint8
	distributionID [distributionIDSize]byte
	keyID          uint32
	chainIteration uint32
	chainSeed      [senderKeySeedSize]byte

	signingPublic      [32]byte
	signingPrivateSeed [32]byte
	hasPrivate         bool

	messageKeys []messageKey
}

type messageKey struct {
	iteration uint32
	seed      [senderKeySeedSize]byte
}

func (s *state) hasMessageKey(iteration uint32) bool {
	for _, mk := range s.messageKeys {
		if mk.iteration == iteration {
			return true
		}
	}
	return false
}

func (s *state) addMessageKey(mk messageKey) {
	s.messageKeys = append(s.messageKeys, mk)
	if len(s.messageKeys) > maxMessageKeysPerState {
		trim := len(s.messageKeys) - maxMessageKeysPerState
		copy(s.messageKeys, s.messageKeys[trim:])
		for i := len(s.messageKeys) - trim; i < len(s.messageKeys); i++ {
			s.messageKeys[i] = messageKey{}
		}
		s.messageKeys = s.messageKeys[:maxMessageKeysPerState]
	}
}

func (s *state) removeMessageKey(iteration uint32) (seed [senderKeySeedSize]byte, ok bool) {
	for i, mk := range s.messageKeys {
		if mk.iteration != iteration {
			continue
		}
		seed = mk.seed
		copy(s.messageKeys[i:], s.messageKeys[i+1:])
		s.messageKeys[len(s.messageKeys)-1] = messageKey{}
		s.messageKeys = s.messageKeys[:len(s.messageKeys)-1]
		return seed, true
	}
	return seed, false
}
