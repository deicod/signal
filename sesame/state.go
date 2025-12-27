package sesame

import "time"

// State is the persisted Sesame roster state for the local device.
type State struct {
	users map[string]*userRecord
}

// NewState returns an empty Sesame state.
func NewState() *State {
	return &State{
		users: make(map[string]*userRecord),
	}
}

type userRecord struct {
	stale      bool
	staleSince time.Time
	devices    map[uint32]*deviceRecord
}

type deviceRecord struct {
	stale      bool
	staleSince time.Time
}

func (s *State) user(id string) *userRecord {
	if s == nil {
		return nil
	}
	return s.users[id]
}

func (s *State) getOrCreateUser(id string) *userRecord {
	if s.users == nil {
		s.users = make(map[string]*userRecord)
	}
	rec := s.users[id]
	if rec == nil {
		rec = &userRecord{
			devices: make(map[uint32]*deviceRecord),
		}
		s.users[id] = rec
	}
	if rec.devices == nil {
		rec.devices = make(map[uint32]*deviceRecord)
	}
	return rec
}
