package sesame

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"time"

	signalerrors "github.com/deicod/signal/errors"
)

var stateSerializeMagic = [4]byte{'S', 'I', 'G', 'S'}

const (
	stateSerializeVersion byte = 1
	stateMinSize               = 4 + 1 + 4
)

// Serialize encodes the state for persistence.
func (s *State) Serialize() ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("%w: sesame state is nil", signalerrors.ErrInvalidMessage)
	}

	userIDs := make([]string, 0, len(s.users))
	for id := range s.users {
		userIDs = append(userIDs, id)
	}
	sort.Strings(userIDs)

	out := make([]byte, 0, stateMinSize+len(userIDs)*32)
	out = append(out, stateSerializeMagic[:]...)
	out = append(out, stateSerializeVersion)
	out = binary.BigEndian.AppendUint32(out, uint32(len(userIDs)))

	for _, userID := range userIDs {
		rec := s.users[userID]
		if rec == nil {
			return nil, fmt.Errorf("%w: sesame state contains nil user record", signalerrors.ErrInvalidMessage)
		}

		if len(userID) > 0xffff {
			return nil, fmt.Errorf("%w: sesame user id too long", signalerrors.ErrInvalidMessage)
		}
		out = binary.BigEndian.AppendUint16(out, uint16(len(userID)))
		out = append(out, userID...)

		var flags byte
		if rec.stale {
			flags |= 1
		}
		out = append(out, flags)
		out = binary.BigEndian.AppendUint64(out, uint64(unixSeconds(rec.staleSince)))

		deviceIDs := make([]uint32, 0, len(rec.devices))
		for id := range rec.devices {
			deviceIDs = append(deviceIDs, id)
		}
		sort.Slice(deviceIDs, func(i, j int) bool { return deviceIDs[i] < deviceIDs[j] })

		out = binary.BigEndian.AppendUint32(out, uint32(len(deviceIDs)))
		for _, deviceID := range deviceIDs {
			dr := rec.devices[deviceID]
			if dr == nil {
				return nil, fmt.Errorf("%w: sesame state contains nil device record", signalerrors.ErrInvalidMessage)
			}

			out = binary.BigEndian.AppendUint32(out, deviceID)
			flags = 0
			if dr.stale {
				flags |= 1
			}
			out = append(out, flags)
			out = binary.BigEndian.AppendUint64(out, uint64(unixSeconds(dr.staleSince)))
		}
	}

	return out, nil
}

// DeserializeState reconstructs a State from serialized bytes.
func DeserializeState(data []byte) (*State, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: sesame state: empty data", signalerrors.ErrInvalidMessage)
	}
	if len(data) < stateMinSize ||
		!bytes.Equal(data[:4], stateSerializeMagic[:]) {
		return nil, fmt.Errorf("%w: sesame state: unsupported format", signalerrors.ErrInvalidMessage)
	}

	pos := 4
	version := data[pos]
	pos++
	if version != stateSerializeVersion {
		return nil, fmt.Errorf("%w: sesame state: unsupported version %d", signalerrors.ErrInvalidMessage, version)
	}
	if pos+4 > len(data) {
		return nil, fmt.Errorf("%w: sesame state: truncated header", signalerrors.ErrInvalidMessage)
	}

	userCount := int(binary.BigEndian.Uint32(data[pos : pos+4]))
	pos += 4
	if userCount < 0 {
		return nil, fmt.Errorf("%w: sesame state: invalid user count", signalerrors.ErrInvalidMessage)
	}

	state := NewState()

	for i := 0; i < userCount; i++ {
		if pos+2 > len(data) {
			return nil, fmt.Errorf("%w: sesame state: truncated user id length", signalerrors.ErrInvalidMessage)
		}
		userIDLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
		pos += 2
		if userIDLen < 0 || pos+userIDLen > len(data) {
			return nil, fmt.Errorf("%w: sesame state: truncated user id", signalerrors.ErrInvalidMessage)
		}
		userID := string(data[pos : pos+userIDLen])
		pos += userIDLen

		const userFixedSize = 1 + 8 + 4
		if pos+userFixedSize > len(data) {
			return nil, fmt.Errorf("%w: sesame state: truncated user record", signalerrors.ErrInvalidMessage)
		}
		flags := data[pos]
		pos++
		staleSince := int64(binary.BigEndian.Uint64(data[pos : pos+8]))
		pos += 8

		deviceCount := int(binary.BigEndian.Uint32(data[pos : pos+4]))
		pos += 4
		if deviceCount < 0 {
			return nil, fmt.Errorf("%w: sesame state: invalid device count", signalerrors.ErrInvalidMessage)
		}

		rec := state.getOrCreateUser(userID)
		rec.stale = (flags & 1) == 1
		rec.staleSince = timeFromUnixSeconds(staleSince)

		for j := 0; j < deviceCount; j++ {
			const devFixedSize = 4 + 1 + 8
			if pos+devFixedSize > len(data) {
				return nil, fmt.Errorf("%w: sesame state: truncated device record", signalerrors.ErrInvalidMessage)
			}
			deviceID := binary.BigEndian.Uint32(data[pos : pos+4])
			pos += 4
			devFlags := data[pos]
			pos++
			devStaleSince := int64(binary.BigEndian.Uint64(data[pos : pos+8]))
			pos += 8

			rec.devices[deviceID] = &deviceRecord{
				stale:      (devFlags & 1) == 1,
				staleSince: timeFromUnixSeconds(devStaleSince),
			}
		}
	}

	if pos != len(data) {
		return nil, fmt.Errorf("%w: sesame state: trailing data", signalerrors.ErrInvalidMessage)
	}

	return state, nil
}

func unixSeconds(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UTC().Unix()
}

func timeFromUnixSeconds(sec int64) time.Time {
	if sec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0).UTC()
}
