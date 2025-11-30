package session

import (
	"bytes"
	"encoding/gob"
	"fmt"

	"github.com/deicod/signal/keys"
	"github.com/deicod/signal/ratchet"
)

// DefaultMaxArchivedSessions bounds archived sessions to control memory usage.
const DefaultMaxArchivedSessions = 5

// Record tracks the current session and archived prior sessions.
type Record struct {
	current     *Session
	archived    []*Session
	maxArchived int
}

// NewRecord creates a record with the given current session and archive limit.
func NewRecord(current *Session, maxArchived int) (*Record, error) {
	if current == nil {
		return nil, fmt.Errorf("record: current session required")
	}
	if maxArchived <= 0 {
		maxArchived = DefaultMaxArchivedSessions
	}
	return &Record{
		current:     current.clone(),
		archived:    nil,
		maxArchived: maxArchived,
	}, nil
}

// Current returns the active session.
func (r *Record) Current() *Session {
	if r == nil {
		return nil
	}
	return r.current
}

// Previous returns archived sessions, newest first.
func (r *Record) Previous() []*Session {
	if r == nil {
		return nil
	}
	return r.archived
}

// Promote replaces the current session with next and archives the prior one,
// truncating archives to maxArchived.
func (r *Record) Promote(next *Session) error {
	if r == nil {
		return fmt.Errorf("record: nil record")
	}
	if next == nil {
		return fmt.Errorf("record: next session required")
	}
	if r.current != nil {
		r.archived = append([]*Session{r.current.clone()}, r.archived...)
		if len(r.archived) > r.maxArchived {
			r.archived = r.archived[:r.maxArchived]
		}
	}
	r.current = next.clone()
	return nil
}

// MaxArchived returns the archive capacity.
func (r *Record) MaxArchived() int {
	if r == nil {
		return 0
	}
	return r.maxArchived
}

// Serialize encodes the record for persistence.
func (r *Record) Serialize() ([]byte, error) {
	if r == nil || r.current == nil {
		return nil, fmt.Errorf("record: nothing to serialize")
	}
	wire := wireRecord{
		MaxArchived: r.maxArchived,
	}

	cur, err := sessionToWire(r.current)
	if err != nil {
		return nil, err
	}
	wire.Current = cur

	for _, s := range r.archived {
		ws, err := sessionToWire(s)
		if err != nil {
			return nil, err
		}
		wire.Archived = append(wire.Archived, ws)
	}

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(&wire); err != nil {
		return nil, fmt.Errorf("record: encode: %w", err)
	}
	return buf.Bytes(), nil
}

// DeserializeRecord reconstructs a Record from serialized bytes.
func DeserializeRecord(data []byte) (*Record, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("record: empty data")
	}
	var wire wireRecord
	dec := gob.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&wire); err != nil {
		return nil, fmt.Errorf("record: decode: %w", err)
	}

	current, err := wireToSession(wire.Current)
	if err != nil {
		return nil, err
	}
	rec := &Record{
		current:     current,
		maxArchived: wire.MaxArchived,
	}
	if rec.maxArchived <= 0 {
		rec.maxArchived = DefaultMaxArchivedSessions
	}
	for _, ws := range wire.Archived {
		s, err := wireToSession(ws)
		if err != nil {
			return nil, err
		}
		rec.archived = append(rec.archived, s)
	}
	if len(rec.archived) > rec.maxArchived {
		rec.archived = rec.archived[:rec.maxArchived]
	}
	return rec, nil
}

// sessionToWire converts a Session to a serializable form.
func sessionToWire(s *Session) (wireSession, error) {
	if s == nil {
		return wireSession{}, fmt.Errorf("record: session is nil")
	}
	if s.ratchetState == nil || s.localIdentity == nil || s.remoteIdentity == nil {
		return wireSession{}, fmt.Errorf("record: session incomplete")
	}
	ws := wireSession{
		Version:        s.version,
		RatchetState:   s.ratchetState.Clone(),
		LocalIdentity:  *s.localIdentity,
		RemoteIdentity: *s.remoteIdentity,
		AssociatedData: append([]byte(nil), s.associatedData...),
	}
	ws.PreviousStates = cloneStateSlice(s.previousStates)
	return ws, nil
}

func wireToSession(ws wireSession) (*Session, error) {
	if ws.RatchetState == nil {
		return nil, fmt.Errorf("record: ratchet state missing")
	}
	s := &Session{
		ratchetState:   ws.RatchetState.Clone(),
		localIdentity:  &ws.LocalIdentity,
		remoteIdentity: &ws.RemoteIdentity,
		associatedData: append([]byte(nil), ws.AssociatedData...),
		previousStates: cloneStateSlice(ws.PreviousStates),
		version:        ws.Version,
	}
	if s.version == 0 {
		s.version = CurrentVersion
	}
	return s, nil
}

// wireRecord and wireSession are gob-serializable containers.
type wireRecord struct {
	MaxArchived int
	Current     wireSession
	Archived    []wireSession
}

type wireSession struct {
	Version        uint8
	RatchetState   *ratchet.State
	LocalIdentity  keys.IdentityKey
	RemoteIdentity keys.IdentityKey
	AssociatedData []byte
	PreviousStates []*ratchet.State
}

func init() {
	gob.Register(wireRecord{})
	gob.Register(wireSession{})
	gob.Register(&ratchet.State{})
	gob.Register(&keys.IdentityKey{})
	gob.Register(&ratchet.Message{})
}
