package session

import (
	"testing"

	"github.com/deicod/signal/keys"
	"github.com/deicod/signal/store"
	"github.com/deicod/signal/store/memory"
)

func FuzzWireCipherDecryptDoesNotPanic(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add([]byte{1, 2, 3, 4, 5})

	f.Fuzz(func(t *testing.T, data []byte) {
		id, _ := keys.GenerateIdentityKeyPair()
		ps := memory.NewStore(id, 1)
		c := NewWireCipher(ps, store.Address{Name: "peer", Device: 1})
		_, _ = c.Decrypt(data)
	})
}
