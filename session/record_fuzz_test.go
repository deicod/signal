package session

import "testing"

func FuzzDeserializeRecordDoesNotPanic(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte("SIGR"))

	// Minimal well-formed record containing a minimal session with a minimal ratchet state.
	seed := make([]byte, 0, 300)
	seed = append(seed, []byte("SIGR")...)
	seed = append(seed, 1)          // record version
	seed = append(seed, 0, 1)       // maxArchived = 1
	seed = append(seed, 0, 0, 1, 6) // current session length = 262

	sessionBytes := make([]byte, 0, 262)
	sessionBytes = append(sessionBytes, 1) // session serialize version
	sessionBytes = append(sessionBytes, 1) // session version

	local := make([]byte, 65)
	local[0] = 1
	remote := make([]byte, 65)
	remote[0] = 1
	sessionBytes = append(sessionBytes, local...)
	sessionBytes = append(sessionBytes, remote...)

	sessionBytes = append(sessionBytes, 0, 0, 0, 0) // adLen = 0

	sessionBytes = append(sessionBytes, 0, 0, 0, 118) // stateLen = 118
	stateBytes := make([]byte, 118)
	stateBytes[0] = 1 // ratchet state version
	stateBytes[1] = 0 // flags
	sessionBytes = append(sessionBytes, stateBytes...)

	sessionBytes = append(sessionBytes, 0, 0, 0, 0) // prevCount = 0
	seed = append(seed, sessionBytes...)
	seed = append(seed, 0, 0) // archivedCount = 0

	f.Add(seed)

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DeserializeRecord(data)
	})
}
