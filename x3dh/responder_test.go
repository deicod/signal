package x3dh

import (
	"testing"

	signalcrypto "github.com/deicod/signal/crypto"
	"github.com/deicod/signal/keys"
	"github.com/deicod/signal/store/memory"
	"github.com/stretchr/testify/require"
)

func TestResponderDerivesSameSecretWithAndWithoutPreKey(t *testing.T) {
	cases := []struct {
		name       string
		includePre bool
	}{
		{name: "WithPreKey", includePre: true},
		{name: "WithoutPreKey", includePre: false},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			initID, err := keys.GenerateIdentityKeyPair()
			require.NoError(t, err)
			respID, err := keys.GenerateIdentityKeyPair()
			require.NoError(t, err)
			signed, err := keys.GenerateSignedPreKey(respID, 5)
			require.NoError(t, err)
			kyber, err := keys.GenerateKyberPreKey(respID, 12)
			require.NoError(t, err)

			var pre *keys.PreKey
			if tt.includePre {
				pre, err = keys.GeneratePreKey(9)
				require.NoError(t, err)
			}

			bundle, err := keys.NewPreKeyBundleWithKyber(1, 1, pre, signed, kyber, respID.PublicKey)
			require.NoError(t, err)

			initiator := NewInitiator(initID)
			initResult, err := initiator.ProcessPreKeyBundle(bundle)
			require.NoError(t, err)

			store := memory.NewStore(respID, 1)
			if tt.includePre {
				require.NoError(t, store.StorePreKey(pre.ID, pre))
			}
			require.NoError(t, store.StoreKyberPreKey(kyber.ID, kyber))

			responder := NewResponder(respID, signed, store, store)
			respResult, err := responder.ProcessInitialMessage(&initResult.InitialMessage)
			require.NoError(t, err)
			require.Equal(t, initResult.SharedSecret, respResult.SharedSecret)
			require.Equal(t, initResult.InitialMessage.EphemeralKey, respResult.InitialMessage.EphemeralKey)
			require.Equal(t, initResult.InitialMessage.IdentityKey, respResult.InitialMessage.IdentityKey)
		})
	}
}

func TestResponderMissingPreKeyFails(t *testing.T) {
	initID, _ := keys.GenerateIdentityKeyPair()
	respID, _ := keys.GenerateIdentityKeyPair()
	signed, _ := keys.GenerateSignedPreKey(respID, 5)
	pre, _ := keys.GeneratePreKey(9)
	kyber, _ := keys.GenerateKyberPreKey(respID, 12)
	bundle, _ := keys.NewPreKeyBundleWithKyber(1, 1, pre, signed, kyber, respID.PublicKey)

	initResult, _ := NewInitiator(initID).ProcessPreKeyBundle(bundle)

	store := memory.NewStore(respID, 1)
	// pre-key not stored
	require.NoError(t, store.StoreKyberPreKey(kyber.ID, kyber))
	responder := NewResponder(respID, signed, store, store)
	_, err := responder.ProcessInitialMessage(&initResult.InitialMessage)
	require.Error(t, err)
}

func TestResponderMismatchedSignedPreKeyID(t *testing.T) {
	initID, _ := keys.GenerateIdentityKeyPair()
	respID, _ := keys.GenerateIdentityKeyPair()
	signed, _ := keys.GenerateSignedPreKey(respID, 5)
	kyber, _ := keys.GenerateKyberPreKey(respID, 12)
	bundle, _ := keys.NewPreKeyBundleWithKyber(1, 1, nil, signed, kyber, respID.PublicKey)
	initResult, _ := NewInitiator(initID).ProcessPreKeyBundle(bundle)

	// Tamper SignedPreKeyID to mismatch.
	msg := initResult.InitialMessage
	msg.SignedPreKeyID = 999

	store := memory.NewStore(respID, 1)
	require.NoError(t, store.StoreKyberPreKey(kyber.ID, kyber))
	responder := NewResponder(respID, signed, store, store)
	_, err := responder.ProcessInitialMessage(&msg)
	require.Error(t, err)
}

func TestResponderDeletesOneTimePreKey(t *testing.T) {
	initID, _ := keys.GenerateIdentityKeyPair()
	respID, _ := keys.GenerateIdentityKeyPair()
	signed, _ := keys.GenerateSignedPreKey(respID, 5)
	pre, _ := keys.GeneratePreKey(9)
	kyber, _ := keys.GenerateKyberPreKey(respID, 12)
	bundle, _ := keys.NewPreKeyBundleWithKyber(1, 1, pre, signed, kyber, respID.PublicKey)
	initResult, _ := NewInitiator(initID).ProcessPreKeyBundle(bundle)

	store := memory.NewStore(respID, 1)
	require.NoError(t, store.StorePreKey(pre.ID, pre))
	require.NoError(t, store.StoreKyberPreKey(kyber.ID, kyber))
	responder := NewResponder(respID, signed, store, store)

	_, err := responder.ProcessInitialMessage(&initResult.InitialMessage)
	require.NoError(t, err)
	require.False(t, store.ContainsPreKey(pre.ID), "pre-key should be removed after use")
}

func TestResponderSharedSecretMatchesManualDH(t *testing.T) {
	initID, _ := keys.GenerateIdentityKeyPair()
	respID, _ := keys.GenerateIdentityKeyPair()
	signed, _ := keys.GenerateSignedPreKey(respID, 5)
	kyber, _ := keys.GenerateKyberPreKey(respID, 12)
	bundle, _ := keys.NewPreKeyBundleWithKyber(1, 1, nil, signed, kyber, respID.PublicKey)
	initResult, _ := NewInitiator(initID).ProcessPreKeyBundle(bundle)

	store := memory.NewStore(respID, 1)
	require.NoError(t, store.StoreKyberPreKey(kyber.ID, kyber))
	responder := NewResponder(respID, signed, store, store)
	respResult, err := responder.ProcessInitialMessage(&initResult.InitialMessage)
	require.NoError(t, err)

	// Manual DH to verify shared secret.
	dh1, _ := signalcrypto.DH(signed.KeyPair.PrivateKey, initID.PublicKey.PublicKey)
	dh2, _ := signalcrypto.DH(respID.PrivateKey, initResult.InitialMessage.EphemeralKey)
	dh3, _ := signalcrypto.DH(signed.KeyPair.PrivateKey, initResult.InitialMessage.EphemeralKey)
	ikm := append(append([]byte{}, discontinuity...), dh1[:]...)
	ikm = append(ikm, dh2[:]...)
	ikm = append(ikm, dh3[:]...)
	kyberSS, err := signalcrypto.Kyber1024Decapsulate(kyber.KeyPair.PrivateKey, initResult.InitialMessage.KyberCiphertext)
	require.NoError(t, err)
	ikm = append(ikm, kyberSS...)
	expectedRoot, expectedChain, err := derivePQSecret(ikm)
	require.NoError(t, err)
	require.Equal(t, expectedRoot, respResult.SharedSecret)
	require.NotNil(t, respResult.InitialChainKey)
	require.Equal(t, expectedChain, *respResult.InitialChainKey)
	require.Equal(t, AssociatedData(initID.PublicKey, respID.PublicKey), respResult.AssociatedData)
}
