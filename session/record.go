package session

import (
	"encoding/binary"
	"fmt"

	signalerrors "github.com/deicod/signal/errors"
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
	if len(r.archived) > 0 {
		filtered := r.archived[:0]
		for _, s := range r.archived {
			if s == next {
				continue
			}
			filtered = append(filtered, s)
		}
		for i := len(filtered); i < len(r.archived); i++ {
			r.archived[i] = nil
		}
		r.archived = filtered
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
		return nil, fmt.Errorf("%w: record: nothing to serialize", signalerrors.ErrInvalidMessage)
	}

	maxArchived := r.maxArchived
	if maxArchived <= 0 {
		maxArchived = DefaultMaxArchivedSessions
	}

	currentBytes, err := serializeSession(r.current)
	if err != nil {
		return nil, err
	}

	archived := r.archived
	if len(archived) > maxArchived {
		archived = archived[:maxArchived]
	}

	out := make([]byte, 0, 4+1+2+4+len(currentBytes)+2+len(archived)*(4+64))
	out = append(out, recordSerializeMagic[:]...)
	out = append(out, recordSerializeVersion)
	out = binary.BigEndian.AppendUint16(out, uint16(maxArchived))

	out = binary.BigEndian.AppendUint32(out, uint32(len(currentBytes)))
	out = append(out, currentBytes...)

	out = binary.BigEndian.AppendUint16(out, uint16(len(archived)))
	for _, s := range archived {
		sb, err := serializeSession(s)
		if err != nil {
			return nil, err
		}
		out = binary.BigEndian.AppendUint32(out, uint32(len(sb)))
		out = append(out, sb...)
	}

	return out, nil
}

// DeserializeRecord reconstructs a Record from serialized bytes.
func DeserializeRecord(data []byte) (*Record, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: record: empty data", signalerrors.ErrInvalidMessage)
	}
	if len(data) < recordMinSize ||
		data[0] != recordSerializeMagic[0] ||
		data[1] != recordSerializeMagic[1] ||
		data[2] != recordSerializeMagic[2] ||
		data[3] != recordSerializeMagic[3] {
		return nil, fmt.Errorf("%w: record: unsupported format", signalerrors.ErrInvalidMessage)
	}

	pos := 0
	pos += 4
	version := data[pos]
	pos++
	if version != recordSerializeVersion {
		return nil, fmt.Errorf("%w: record: unsupported version %d", signalerrors.ErrInvalidMessage, version)
	}
	if pos+2+4+2 > len(data) {
		return nil, fmt.Errorf("%w: record: truncated header", signalerrors.ErrInvalidMessage)
	}

	maxArchived := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	if maxArchived <= 0 {
		maxArchived = DefaultMaxArchivedSessions
	}

	curLen := int(binary.BigEndian.Uint32(data[pos : pos+4]))
	pos += 4
	if curLen <= 0 || pos+curLen > len(data) {
		return nil, fmt.Errorf("%w: record: invalid current length", signalerrors.ErrInvalidMessage)
	}
	current, err := deserializeSession(data[pos : pos+curLen])
	if err != nil {
		return nil, err
	}
	pos += curLen

	archivedCount := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	if archivedCount < 0 {
		return nil, fmt.Errorf("%w: record: invalid archived count", signalerrors.ErrInvalidMessage)
	}

	rec := &Record{
		current:     current,
		maxArchived: maxArchived,
	}

	for i := 0; i < archivedCount; i++ {
		if pos+4 > len(data) {
			return nil, fmt.Errorf("%w: record: truncated archived length", signalerrors.ErrInvalidMessage)
		}
		sLen := int(binary.BigEndian.Uint32(data[pos : pos+4]))
		pos += 4
		if sLen <= 0 || pos+sLen > len(data) {
			return nil, fmt.Errorf("%w: record: invalid archived length", signalerrors.ErrInvalidMessage)
		}
		if len(rec.archived) < rec.maxArchived {
			sess, err := deserializeSession(data[pos : pos+sLen])
			if err != nil {
				return nil, err
			}
			rec.archived = append(rec.archived, sess)
		}
		pos += sLen
	}

	if pos != len(data) {
		return nil, fmt.Errorf("%w: record: trailing data", signalerrors.ErrInvalidMessage)
	}

	return rec, nil
}

var recordSerializeMagic = [4]byte{'S', 'I', 'G', 'R'}

const (
	recordSerializeVersion byte = 1
	recordMinSize               = 4 + 1 + 2 + 4 + 2
)

const (
	sessionSerializeVersion byte = 1
	sessionIdentitySize          = 1 + 32 + 32
)

func serializeSession(s *Session) ([]byte, error) {
	if s == nil || s.ratchetState == nil || s.localIdentity == nil || s.remoteIdentity == nil {
		return nil, fmt.Errorf("%w: record: session incomplete", signalerrors.ErrInvalidMessage)
	}

	localID, err := s.localIdentity.Serialize()
	if err != nil {
		return nil, fmt.Errorf("%w: record: serialize local identity: %v", signalerrors.ErrInvalidMessage, err)
	}
	remoteID, err := s.remoteIdentity.Serialize()
	if err != nil {
		return nil, fmt.Errorf("%w: record: serialize remote identity: %v", signalerrors.ErrInvalidMessage, err)
	}
	if len(localID) != sessionIdentitySize || len(remoteID) != sessionIdentitySize {
		return nil, fmt.Errorf("%w: record: unexpected identity size", signalerrors.ErrInvalidMessage)
	}

	stateBytes, err := s.ratchetState.Serialize()
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, 1+1+sessionIdentitySize*2+4+len(s.associatedData)+4+len(stateBytes)+4+len(s.previousStates)*(4+64))
	out = append(out, sessionSerializeVersion)
	version := s.version
	if version == 0 {
		version = CurrentVersion
	}
	out = append(out, version)
	out = append(out, localID...)
	out = append(out, remoteID...)

	out = binary.BigEndian.AppendUint32(out, uint32(len(s.associatedData)))
	out = append(out, s.associatedData...)

	out = binary.BigEndian.AppendUint32(out, uint32(len(stateBytes)))
	out = append(out, stateBytes...)

	prevStates := s.previousStates
	out = binary.BigEndian.AppendUint32(out, uint32(len(prevStates)))
	for _, st := range prevStates {
		if st == nil {
			out = binary.BigEndian.AppendUint32(out, 0)
			continue
		}
		sb, err := st.Serialize()
		if err != nil {
			return nil, err
		}
		out = binary.BigEndian.AppendUint32(out, uint32(len(sb)))
		out = append(out, sb...)
	}

	return out, nil
}

func deserializeSession(data []byte) (*Session, error) {
	if len(data) < 1+1+sessionIdentitySize*2+4+4+4 {
		return nil, fmt.Errorf("%w: record: session too short", signalerrors.ErrInvalidMessage)
	}

	pos := 0
	ver := data[pos]
	pos++
	if ver != sessionSerializeVersion {
		return nil, fmt.Errorf("%w: record: session unsupported version %d", signalerrors.ErrInvalidMessage, ver)
	}
	sessionVersion := data[pos]
	pos++
	if sessionVersion == 0 {
		sessionVersion = CurrentVersion
	}

	localID, err := keys.DeserializeIdentityKey(data[pos : pos+sessionIdentitySize])
	if err != nil {
		return nil, fmt.Errorf("%w: record: %v", signalerrors.ErrInvalidMessage, err)
	}
	pos += sessionIdentitySize
	remoteID, err := keys.DeserializeIdentityKey(data[pos : pos+sessionIdentitySize])
	if err != nil {
		return nil, fmt.Errorf("%w: record: %v", signalerrors.ErrInvalidMessage, err)
	}
	pos += sessionIdentitySize

	if pos+4 > len(data) {
		return nil, fmt.Errorf("%w: record: session truncated ad length", signalerrors.ErrInvalidMessage)
	}
	adLen := int(binary.BigEndian.Uint32(data[pos : pos+4]))
	pos += 4
	if adLen < 0 || pos+adLen > len(data) {
		return nil, fmt.Errorf("%w: record: session invalid ad length", signalerrors.ErrInvalidMessage)
	}
	ad := append([]byte(nil), data[pos:pos+adLen]...)
	pos += adLen

	if pos+4 > len(data) {
		return nil, fmt.Errorf("%w: record: session truncated state length", signalerrors.ErrInvalidMessage)
	}
	stateLen := int(binary.BigEndian.Uint32(data[pos : pos+4]))
	pos += 4
	if stateLen <= 0 || pos+stateLen > len(data) {
		return nil, fmt.Errorf("%w: record: session invalid state length", signalerrors.ErrInvalidMessage)
	}
	st, err := ratchet.DeserializeState(data[pos : pos+stateLen])
	if err != nil {
		return nil, err
	}
	pos += stateLen

	if pos+4 > len(data) {
		return nil, fmt.Errorf("%w: record: session truncated previous count", signalerrors.ErrInvalidMessage)
	}
	prevCount := int(binary.BigEndian.Uint32(data[pos : pos+4]))
	pos += 4
	if prevCount < 0 || prevCount > 1000 {
		return nil, fmt.Errorf("%w: record: session invalid previous count", signalerrors.ErrInvalidMessage)
	}
	prev := make([]*ratchet.State, 0, prevCount)
	for i := 0; i < prevCount; i++ {
		if pos+4 > len(data) {
			return nil, fmt.Errorf("%w: record: session truncated previous length", signalerrors.ErrInvalidMessage)
		}
		pLen := int(binary.BigEndian.Uint32(data[pos : pos+4]))
		pos += 4
		if pLen == 0 {
			prev = append(prev, nil)
			continue
		}
		if pLen < 0 || pos+pLen > len(data) {
			return nil, fmt.Errorf("%w: record: session invalid previous length", signalerrors.ErrInvalidMessage)
		}
		ps, err := ratchet.DeserializeState(data[pos : pos+pLen])
		if err != nil {
			return nil, err
		}
		prev = append(prev, ps)
		pos += pLen
	}

	if pos != len(data) {
		return nil, fmt.Errorf("%w: record: session trailing data", signalerrors.ErrInvalidMessage)
	}

	return &Session{
		ratchetState:   st,
		localIdentity:  localID,
		remoteIdentity: remoteID,
		associatedData: ad,
		previousStates: prev,
		version:        sessionVersion,
	}, nil
}
