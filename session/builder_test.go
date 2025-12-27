package session

import (
	"testing"

	signalerrors "github.com/deicod/signal/errors"
	"github.com/deicod/signal/keys"
	"github.com/deicod/signal/store"
	"github.com/deicod/signal/store/memory"
	"github.com/stretchr/testify/require"
)

func TestProcessPreKeyBundleCreatesSession(t *testing.T) {
	aliceID, _ := keys.GenerateIdentityKeyPair()
	bobID, _ := keys.GenerateIdentityKeyPair()
	signed, _ := keys.GenerateSignedPreKey(bobID, 5)
	pre, _ := keys.GeneratePreKey(7)
	kyber, _ := keys.GenerateKyberPreKey(bobID, 9)

	bundle, err := keys.NewPreKeyBundleWithKyber(1, 1, pre, signed, kyber, bobID.PublicKey)
	require.NoError(t, err)

	storeAlice := memory.NewStore(aliceID, 1)
	builder := NewBuilder(storeAlice, store.Address{Name: "bob", Device: 1})

	session, msg, err := builder.ProcessPreKeyBundle(bundle)
	require.NoError(t, err)
	require.NotNil(t, session)
	require.NotNil(t, msg)
	require.Equal(t, aliceID.PublicKey, msg.IdentityKey)
	require.Equal(t, bobID.PublicKey, *session.remoteIdentity)

	saved, _ := storeAlice.GetIdentity(store.Address{Name: "bob", Device: 1})
	require.NotNil(t, saved)
	require.Equal(t, bobID.PublicKey, *saved)
}

func TestProcessPreKeyBundleRejectsUntrusted(t *testing.T) {
	aliceID, _ := keys.GenerateIdentityKeyPair()
	bobID, _ := keys.GenerateIdentityKeyPair()
	otherID, _ := keys.GenerateIdentityKeyPair()
	signed, _ := keys.GenerateSignedPreKey(bobID, 5)
	kyber, _ := keys.GenerateKyberPreKey(bobID, 9)

	bundle, err := keys.NewPreKeyBundleWithKyber(1, 1, nil, signed, kyber, bobID.PublicKey)
	require.NoError(t, err)

	storeAlice := memory.NewStore(aliceID, 1)
	addr := store.Address{Name: "bob", Device: 1}
	require.NoError(t, storeAlice.SaveIdentity(addr, &otherID.PublicKey))

	builder := NewBuilder(storeAlice, addr)
	session, msg, err := builder.ProcessPreKeyBundle(bundle)
	require.ErrorIs(t, err, signalerrors.ErrUntrustedIdentity)
	require.Nil(t, session)
	require.Nil(t, msg)
}

func TestProcessPreKeyMessageCreatesSession(t *testing.T) {
	aliceID, _ := keys.GenerateIdentityKeyPair()
	bobID, _ := keys.GenerateIdentityKeyPair()
	signed, _ := keys.GenerateSignedPreKey(bobID, 5)
	pre, _ := keys.GeneratePreKey(7)
	kyber, _ := keys.GenerateKyberPreKey(bobID, 9)

	bundle, err := keys.NewPreKeyBundleWithKyber(1, 1, pre, signed, kyber, bobID.PublicKey)
	require.NoError(t, err)

	// Alice builds initial message.
	storeAlice := memory.NewStore(aliceID, 1)
	addrBob := store.Address{Name: "bob", Device: 1}
	initBuilder := NewBuilder(storeAlice, addrBob)
	initSession, initMsg, err := initBuilder.ProcessPreKeyBundle(bundle)
	require.NoError(t, err)
	require.NotNil(t, initSession)

	// Bob processes incoming message.
	storeBob := memory.NewStore(bobID, 2)
	require.NoError(t, storeBob.StoreSignedPreKey(signed.ID, signed))
	require.NoError(t, storeBob.StoreKyberPreKey(kyber.ID, kyber))
	if pre != nil {
		require.NoError(t, storeBob.StorePreKey(pre.ID, pre))
	}

	respBuilder := NewBuilder(storeBob, store.Address{Name: "alice", Device: 1})
	session, ad, err := respBuilder.ProcessPreKeyMessage(initMsg)
	require.NoError(t, err)
	require.NotNil(t, session)
	require.NotEmpty(t, ad)
	require.Equal(t, aliceID.PublicKey, *session.remoteIdentity)

	saved, _ := storeBob.GetIdentity(store.Address{Name: "alice", Device: 1})
	require.NotNil(t, saved)
	require.Equal(t, aliceID.PublicKey, *saved)
}

func TestProcessPreKeyMessageRejectsUntrusted(t *testing.T) {
	aliceID, _ := keys.GenerateIdentityKeyPair()
	bobID, _ := keys.GenerateIdentityKeyPair()
	otherID, _ := keys.GenerateIdentityKeyPair()
	signed, _ := keys.GenerateSignedPreKey(bobID, 5)
	pre, _ := keys.GeneratePreKey(7)
	kyber, _ := keys.GenerateKyberPreKey(bobID, 9)

	bundle, err := keys.NewPreKeyBundleWithKyber(1, 1, pre, signed, kyber, bobID.PublicKey)
	require.NoError(t, err)

	storeAlice := memory.NewStore(aliceID, 1)
	initBuilder := NewBuilder(storeAlice, store.Address{Name: "bob", Device: 1})
	_, initMsg, err := initBuilder.ProcessPreKeyBundle(bundle)
	require.NoError(t, err)

	storeBob := memory.NewStore(bobID, 2)
	require.NoError(t, storeBob.StoreSignedPreKey(signed.ID, signed))
	require.NoError(t, storeBob.StoreKyberPreKey(kyber.ID, kyber))
	if pre != nil {
		require.NoError(t, storeBob.StorePreKey(pre.ID, pre))
	}

	addrAlice := store.Address{Name: "alice", Device: 1}
	require.NoError(t, storeBob.SaveIdentity(addrAlice, &otherID.PublicKey))

	respBuilder := NewBuilder(storeBob, addrAlice)
	session, ad, err := respBuilder.ProcessPreKeyMessage(initMsg)
	require.ErrorIs(t, err, signalerrors.ErrUntrustedIdentity)
	require.Nil(t, session)
	require.Nil(t, ad)
}
