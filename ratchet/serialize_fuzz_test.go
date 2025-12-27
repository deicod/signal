package ratchet

import "testing"

func FuzzDeserializeStateDoesNotPanic(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte{1})

	// Minimal valid state: version(1), flags(0), RK/CKs/CKr(96), Ns/Nr/PN(12),
	// skippedCount(0), seenCount(0).
	seed := make([]byte, 118)
	seed[0] = 1
	seed[1] = 0
	f.Add(seed)

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DeserializeState(data)
	})
}
