package sesame

import "testing"

func FuzzDeserializeStateDoesNotPanic(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte("SIGS"))

	seed := make([]byte, 0, stateMinSize+32)
	seed = append(seed, []byte("SIGS")...)
	seed = append(seed, stateSerializeVersion)
	seed = append(seed, 0, 0, 0, 0) // userCount = 0
	f.Add(seed)

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DeserializeState(data)
	})
}
