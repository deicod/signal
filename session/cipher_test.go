package session

import (
	"testing"

	"github.com/deicod/signal/keys"
	"github.com/deicod/signal/store"
	"github.com/deicod/signal/store/memory"
	"github.com/stretchr/testify/require"
)

func TestSessionCipherEncryptDecrypt(t *testing.T) {
	aliceID, _ := keys.GenerateIdentityKeyPair()
	bobID, _ := keys.GenerateIdentityKeyPair()
	signed, _ := keys.GenerateSignedPreKey(bobID, 3)
	pre, _ := keys.GeneratePreKey(4)

	bundle, err := keys.NewPreKeyBundle(1, 1, pre, signed, bobID.PublicKey)
	require.NoError(t, err)

	storeAlice := memory.NewStore(aliceID, 1)
	addrBob := store.Address{Name: "bob", Device: 1}
	builderAlice := NewSessionBuilder(storeAlice, addrBob)
	sessionA, initMsg, err := builderAlice.ProcessPreKeyBundle(bundle)
	require.NoError(t, err)
	recA, err := NewRecord(sessionA, DefaultMaxArchivedSessions)
	require.NoError(t, err)
	require.NoError(t, storeAlice.StoreSession(addrBob, &store.SessionRecord{Data: recA}))

	storeBob := memory.NewStore(bobID, 2)
	require.NoError(t, storeBob.StoreSignedPreKey(signed.ID, signed))
	if pre != nil {
		require.NoError(t, storeBob.StorePreKey(pre.ID, pre))
	}
	addrAlice := store.Address{Name: "alice", Device: 1}
	builderBob := NewSessionBuilder(storeBob, addrAlice)
	sessionB, _, err := builderBob.ProcessPreKeyMessage(initMsg)
	require.NoError(t, err)
	recB, err := NewRecord(sessionB, DefaultMaxArchivedSessions)
	require.NoError(t, err)
	require.NoError(t, storeBob.StoreSession(addrAlice, &store.SessionRecord{Data: recB}))

	cipherA := NewSessionCipher(storeAlice, addrBob)
	cipherB := NewSessionCipher(storeBob, addrAlice)

	ct, err := cipherA.Encrypt([]byte("hello"))
	require.NoError(t, err)

	pt, err := cipherB.Decrypt(ct)
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), pt)

	resp, err := cipherB.Encrypt([]byte("pong"))
	require.NoError(t, err)
	back, err := cipherA.Decrypt(resp)
	require.NoError(t, err)
	require.Equal(t, []byte("pong"), back)
}

func TestSessionCipherRequiresSession(t *testing.T) {
	id, _ := keys.GenerateIdentityKeyPair()
	protoStore := memory.NewStore(id, 1)
	cipher := NewSessionCipher(protoStore, store.Address{Name: "nobody", Device: 1})
	_, err := cipher.Encrypt([]byte("data"))
	require.Error(t, err)
}
