package session

import (
	"fmt"
	"testing"

	signalerrors "github.com/deicod/signal/errors"
	"github.com/deicod/signal/keys"
	"github.com/deicod/signal/store"
	"github.com/deicod/signal/store/memory"
	"github.com/stretchr/testify/require"
)

func TestCipherReorderingAndDuplicateMessages(t *testing.T) {
	aliceID, _ := keys.GenerateIdentityKeyPair()
	bobID, _ := keys.GenerateIdentityKeyPair()
	signed, _ := keys.GenerateSignedPreKey(bobID, 3)
	kyber, _ := keys.GenerateKyberPreKey(bobID, 4)

	bundle, err := keys.NewPreKeyBundleWithKyber(1, 1, nil, signed, kyber, bobID.PublicKey)
	require.NoError(t, err)

	storeAlice := memory.NewStore(aliceID, 1)
	storeBob := memory.NewStore(bobID, 2)
	require.NoError(t, storeBob.StoreSignedPreKey(signed.ID, signed))
	require.NoError(t, storeBob.StoreKyberPreKey(kyber.ID, kyber))

	addrBob := store.Address{Name: "bob", Device: 1}
	addrAlice := store.Address{Name: "alice", Device: 1}

	cipherA := NewCipher(storeAlice, addrBob)
	cipherB := NewCipher(storeBob, addrAlice)

	initial, err := cipherA.EncryptWithPreKeyBundle(bundle, []byte("init"))
	require.NoError(t, err)
	pt, err := cipherB.Decrypt(initial)
	require.NoError(t, err)
	require.Equal(t, []byte("init"), pt)

	const n = 10
	ciphertexts := make([][]byte, n)
	for i := 0; i < n; i++ {
		ct, err := cipherA.Encrypt([]byte(fmt.Sprintf("msg-%d", i)))
		require.NoError(t, err)
		ciphertexts[i] = ct
	}

	order := []int{9, 0, 5, 5, 3, 1, 2, 4, 6, 7, 8}
	seen := make(map[int]bool, n)
	for _, idx := range order {
		plain, err := cipherB.Decrypt(ciphertexts[idx])
		if idx == 5 && seen[idx] {
			require.Error(t, err)
			require.ErrorIs(t, err, signalerrors.ErrDuplicateMessage)
			continue
		}
		require.NoError(t, err)
		require.Equal(t, []byte(fmt.Sprintf("msg-%d", idx)), plain)
		seen[idx] = true
	}
}

func FuzzCipherDecryptDoesNotPanic(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add([]byte{1, 2, 3, 4, 5})

	f.Fuzz(func(t *testing.T, data []byte) {
		id, _ := keys.GenerateIdentityKeyPair()
		ps := memory.NewStore(id, 1)
		c := NewCipher(ps, store.Address{Name: "peer", Device: 1})
		_, _ = c.Decrypt(data)
	})
}
