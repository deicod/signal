package signal_test

import (
	"errors"
	"testing"

	"github.com/deicod/signal"
	"github.com/deicod/signal/store/memory"
	"github.com/stretchr/testify/require"
)

func TestFanoutCipherEncryptBootstrapsSessions(t *testing.T) {
	aliceID, _ := signal.GenerateIdentityKeyPair()
	aliceStore := memory.NewStore(aliceID, 1)

	bob1ID, _ := signal.GenerateIdentityKeyPair()
	bob1Store := memory.NewStore(bob1ID, 2)
	signed1, _ := signal.GenerateAndStoreSignedPreKey(bob1Store, 1)
	kyber1, _ := signal.GenerateAndStoreKyberPreKey(bob1Store, 2)
	bundle1, _ := signal.BuildPreKeyBundle(bob1Store, 1, nil, signed1.ID, &kyber1.ID)

	bob2ID, _ := signal.GenerateIdentityKeyPair()
	bob2Store := memory.NewStore(bob2ID, 3)
	signed2, _ := signal.GenerateAndStoreSignedPreKey(bob2Store, 1)
	kyber2, _ := signal.GenerateAndStoreKyberPreKey(bob2Store, 2)
	bundle2, _ := signal.BuildPreKeyBundle(bob2Store, 2, nil, signed2.ID, &kyber2.ID)

	bob1Addr := signal.Address{Name: "bob", Device: 1}
	bob2Addr := signal.Address{Name: "bob", Device: 2}

	fanout := signal.NewFanoutCipher(aliceStore)
	out, err := fanout.Encrypt([]byte("hello"), []signal.Recipient{
		{Address: bob1Addr, Bundle: bundle1},
		{Address: bob2Addr, Bundle: bundle2},
	})
	require.NoError(t, err)
	require.Len(t, out, 2)

	bob1Cipher := signal.NewCipher(bob1Store, signal.Address{Name: "alice", Device: 1})
	pt, err := bob1Cipher.Decrypt(out[bob1Addr])
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), pt)

	bob2Cipher := signal.NewCipher(bob2Store, signal.Address{Name: "alice", Device: 1})
	pt, err = bob2Cipher.Decrypt(out[bob2Addr])
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), pt)

	out2, err := fanout.Encrypt([]byte("again"), []signal.Recipient{
		{Address: bob1Addr},
		{Address: bob2Addr},
	})
	require.NoError(t, err)
	require.Len(t, out2, 2)

	pt, err = bob1Cipher.Decrypt(out2[bob1Addr])
	require.NoError(t, err)
	require.Equal(t, []byte("again"), pt)

	pt, err = bob2Cipher.Decrypt(out2[bob2Addr])
	require.NoError(t, err)
	require.Equal(t, []byte("again"), pt)
}

func TestFanoutCipherEncryptRequiresSessionOrBundle(t *testing.T) {
	aliceID, _ := signal.GenerateIdentityKeyPair()
	aliceStore := memory.NewStore(aliceID, 1)

	fanout := signal.NewFanoutCipher(aliceStore)
	_, err := fanout.Encrypt([]byte("hi"), []signal.Recipient{
		{Address: signal.Address{Name: "bob", Device: 1}},
	})
	require.Error(t, err)
	require.True(t, errors.Is(err, signal.ErrNoSession))
}
