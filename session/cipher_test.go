package session

import (
	"testing"

	signalerrors "github.com/deicod/signal/errors"
	"github.com/deicod/signal/keys"
	"github.com/deicod/signal/store"
	"github.com/deicod/signal/store/memory"
	"github.com/stretchr/testify/require"
)

func TestCipherEncryptDecrypt(t *testing.T) {
	aliceID, _ := keys.GenerateIdentityKeyPair()
	bobID, _ := keys.GenerateIdentityKeyPair()
	signed, _ := keys.GenerateSignedPreKey(bobID, 3)
	pre, _ := keys.GeneratePreKey(4)
	kyber, _ := keys.GenerateKyberPreKey(bobID, 9)

	bundle, err := keys.NewPreKeyBundleWithKyber(1, 1, pre, signed, kyber, bobID.PublicKey)
	require.NoError(t, err)

	storeAlice := memory.NewStore(aliceID, 1)
	addrBob := store.Address{Name: "bob", Device: 1}
	builderAlice := NewBuilder(storeAlice, addrBob)
	sessionA, initMsg, err := builderAlice.ProcessPreKeyBundle(bundle)
	require.NoError(t, err)
	recA, err := NewRecord(sessionA, DefaultMaxArchivedSessions)
	require.NoError(t, err)
	dataA, err := recA.Serialize()
	require.NoError(t, err)
	require.NoError(t, storeAlice.StoreSession(addrBob, &store.SessionRecord{Data: dataA}))

	storeBob := memory.NewStore(bobID, 2)
	require.NoError(t, storeBob.StoreSignedPreKey(signed.ID, signed))
	require.NoError(t, storeBob.StoreKyberPreKey(kyber.ID, kyber))
	if pre != nil {
		require.NoError(t, storeBob.StorePreKey(pre.ID, pre))
	}
	addrAlice := store.Address{Name: "alice", Device: 1}
	builderBob := NewBuilder(storeBob, addrAlice)
	sessionB, _, err := builderBob.ProcessPreKeyMessage(initMsg)
	require.NoError(t, err)
	recB, err := NewRecord(sessionB, DefaultMaxArchivedSessions)
	require.NoError(t, err)
	dataB, err := recB.Serialize()
	require.NoError(t, err)
	require.NoError(t, storeBob.StoreSession(addrAlice, &store.SessionRecord{Data: dataB}))

	cipherA := NewCipher(storeAlice, addrBob)
	cipherB := NewCipher(storeBob, addrAlice)

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

func TestCipherPreKeyBootstrap(t *testing.T) {
	aliceID, _ := keys.GenerateIdentityKeyPair()
	bobID, _ := keys.GenerateIdentityKeyPair()
	signed, _ := keys.GenerateSignedPreKey(bobID, 3)
	pre, _ := keys.GeneratePreKey(4)
	kyber, _ := keys.GenerateKyberPreKey(bobID, 9)

	bundle, err := keys.NewPreKeyBundleWithKyber(1, 1, pre, signed, kyber, bobID.PublicKey)
	require.NoError(t, err)

	storeAlice := memory.NewStore(aliceID, 1)
	storeBob := memory.NewStore(bobID, 2)
	require.NoError(t, storeBob.StoreSignedPreKey(signed.ID, signed))
	require.NoError(t, storeBob.StoreKyberPreKey(kyber.ID, kyber))
	require.NoError(t, storeBob.StorePreKey(pre.ID, pre))

	addrBob := store.Address{Name: "bob", Device: 1}
	addrAlice := store.Address{Name: "alice", Device: 1}

	cipherA := NewCipher(storeAlice, addrBob)
	cipherB := NewCipher(storeBob, addrAlice)

	initial, err := cipherA.EncryptWithPreKeyBundle(bundle, []byte("hello"))
	require.NoError(t, err)

	pt, err := cipherB.Decrypt(initial)
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), pt)

	reply, err := cipherB.Encrypt([]byte("pong"))
	require.NoError(t, err)

	back, err := cipherA.Decrypt(reply)
	require.NoError(t, err)
	require.Equal(t, []byte("pong"), back)
}

func TestCipherRequiresSession(t *testing.T) {
	id, _ := keys.GenerateIdentityKeyPair()
	protoStore := memory.NewStore(id, 1)
	cipher := NewCipher(protoStore, store.Address{Name: "nobody", Device: 1})
	_, err := cipher.Encrypt([]byte("data"))
	require.ErrorIs(t, err, signalerrors.ErrNoSession)
}

func TestCipherPreKeyReplayRejected(t *testing.T) {
	aliceID, _ := keys.GenerateIdentityKeyPair()
	bobID, _ := keys.GenerateIdentityKeyPair()
	signed, _ := keys.GenerateSignedPreKey(bobID, 3)
	kyber, _ := keys.GenerateKyberPreKey(bobID, 9)

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

	initial, err := cipherA.EncryptWithPreKeyBundle(bundle, []byte("hello"))
	require.NoError(t, err)

	pt, err := cipherB.Decrypt(initial)
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), pt)

	_, err = cipherB.Decrypt(initial)
	require.Error(t, err)
	require.ErrorIs(t, err, signalerrors.ErrDuplicateMessage)
}

func TestCipherDecryptFallsBackToArchivedSession(t *testing.T) {
	aliceID, _ := keys.GenerateIdentityKeyPair()
	bobID, _ := keys.GenerateIdentityKeyPair()
	signed, _ := keys.GenerateSignedPreKey(bobID, 3)
	kyber, _ := keys.GenerateKyberPreKey(bobID, 9)

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

	initial1, err := cipherA.EncryptWithPreKeyBundle(bundle, []byte("init-1"))
	require.NoError(t, err)
	pt1, err := cipherB.Decrypt(initial1)
	require.NoError(t, err)
	require.Equal(t, []byte("init-1"), pt1)

	oldCt, err := cipherA.Encrypt([]byte("old"))
	require.NoError(t, err)

	require.NoError(t, storeAlice.DeleteSession(addrBob))

	initial2, err := cipherA.EncryptWithPreKeyBundle(bundle, []byte("init-2"))
	require.NoError(t, err)
	pt2, err := cipherB.Decrypt(initial2)
	require.NoError(t, err)
	require.Equal(t, []byte("init-2"), pt2)

	oldPt, err := cipherB.Decrypt(oldCt)
	require.NoError(t, err)
	require.Equal(t, []byte("old"), oldPt)
}
