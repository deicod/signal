package session

import (
	"fmt"

	"github.com/deicod/signal/keys"
	"github.com/deicod/signal/ratchet"
	"github.com/deicod/signal/spqr"
)

// CurrentVersion represents the session version for protocol upgrades.
const CurrentVersion uint8 = 1

// Session encapsulates Double Ratchet state along with identity metadata.
type Session struct {
	ratchetState   *ratchet.State
	pqrState       *spqr.State
	localIdentity  *keys.IdentityKey
	remoteIdentity *keys.IdentityKey
	associatedData []byte
	previousStates []*ratchet.State
	version        uint8
}

// NewSession constructs a Session from an existing ratchet state and peer identities.
func NewSession(state *ratchet.State, localIdentity, remoteIdentity *keys.IdentityKey, associatedData []byte) (*Session, error) {
	if state == nil {
		return nil, fmt.Errorf("session: ratchet state required")
	}
	if localIdentity == nil || remoteIdentity == nil {
		return nil, fmt.Errorf("session: identity keys required")
	}

	local := *localIdentity
	remote := *remoteIdentity

	return &Session{
		ratchetState:   state.Clone(),
		localIdentity:  &local,
		remoteIdentity: &remote,
		associatedData: append([]byte(nil), associatedData...),
		version:        CurrentVersion,
	}, nil
}

// Version returns the session version.
func (s *Session) Version() uint8 {
	if s == nil {
		return 0
	}
	return s.version
}

// AssociatedData returns a copy of the session's associated data.
func (s *Session) AssociatedData() []byte {
	if s == nil {
		return nil
	}
	return append([]byte(nil), s.associatedData...)
}

// CurrentState returns the active ratchet state.
func (s *Session) CurrentState() *ratchet.State {
	if s == nil {
		return nil
	}
	return s.ratchetState
}

// ArchiveState saves the current ratchet state (if any) to previousStates and
// replaces it with newState. maxPrevious controls how many archived states are kept.
// If maxPrevious <= 0, no truncation is applied.
func (s *Session) ArchiveState(newState *ratchet.State, maxPrevious int) error {
	if s == nil {
		return fmt.Errorf("session: nil session")
	}
	if newState == nil {
		return fmt.Errorf("session: new state required")
	}

	if s.ratchetState != nil {
		s.previousStates = append([]*ratchet.State{s.ratchetState.Clone()}, s.previousStates...)
	}

	if maxPrevious > 0 && len(s.previousStates) > maxPrevious {
		s.previousStates = s.previousStates[:maxPrevious]
	}

	s.ratchetState = newState.Clone()
	s.version = CurrentVersion
	return nil
}

// PreviousStates returns archived ratchet states in newest-first order.
func (s *Session) PreviousStates() []*ratchet.State {
	if s == nil {
		return nil
	}
	return s.previousStates
}

func (s *Session) clone() *Session {
	if s == nil {
		return nil
	}
	clone := &Session{
		version:        s.version,
		associatedData: append([]byte(nil), s.associatedData...),
		previousStates: cloneStateSlice(s.previousStates),
	}
	if s.ratchetState != nil {
		clone.ratchetState = s.ratchetState.Clone()
	}
	if s.pqrState != nil {
		clone.pqrState = s.pqrState.Clone()
	}
	if s.localIdentity != nil {
		li := *s.localIdentity
		clone.localIdentity = &li
	}
	if s.remoteIdentity != nil {
		ri := *s.remoteIdentity
		clone.remoteIdentity = &ri
	}
	return clone
}

func cloneStateSlice(states []*ratchet.State) []*ratchet.State {
	out := make([]*ratchet.State, 0, len(states))
	for _, st := range states {
		if st == nil {
			continue
		}
		out = append(out, st.Clone())
	}
	return out
}
