package x3dh

import (
	"testing"

	signalcrypto "github.com/deicod/signal/crypto"
	"github.com/deicod/signal/keys"
	"github.com/stretchr/testify/require"
)

func TestInitiatorDerivesSharedSecretWithAndWithoutPreKey(t *testing.T) {
	cases := []struct {
		name       string
		includePre bool
	}{
		{name: "WithOneTimePreKey", includePre: true},
		{name: "WithoutOneTimePreKey", includePre: false},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			initID, err := keys.GenerateIdentityKeyPair()
			require.NoError(t, err)
			respID, err := keys.GenerateIdentityKeyPair()
			require.NoError(t, err)
			signed, err := keys.GenerateSignedPreKey(respID, 7)
			require.NoError(t, err)
			kyber, err := keys.GenerateKyberPreKey(respID, 12)
			require.NoError(t, err)

			var pre *keys.PreKey
			if tt.includePre {
				pre, err = keys.GeneratePreKey(9)
				require.NoError(t, err)
			}

			bundle, err := keys.NewPreKeyBundleWithKyber(111, 1, pre, signed, kyber, respID.PublicKey)
			require.NoError(t, err)

			initiator := NewInitiator(initID)
			result, err := initiator.ProcessPreKeyBundle(bundle)
			require.NoError(t, err)
			require.NotNil(t, result)
			require.Equal(t, respID.PublicKey, result.RemoteIdentity)
			require.Equal(t, bundle.PreKeyID, result.InitialMessage.PreKeyID)
			require.Equal(t, bundle.SignedPreKeyID, result.InitialMessage.SignedPreKeyID)
			require.Equal(t, bundle.KyberPreKeyID, result.InitialMessage.KyberPreKeyID)
			require.Equal(t, initID.PublicKey, result.InitialMessage.IdentityKey)
			require.Equal(t, initiator.identityKey.PublicKey, result.InitialMessage.IdentityKey)
			require.NotNil(t, result.InitialChainKey)

			// Compute expected shared secret using responder's perspective.
			dh1, err := signalcrypto.DH(signed.KeyPair.PrivateKey, initID.PublicKey.PublicKey)
			require.NoError(t, err)
			dh2, err := signalcrypto.DH(respID.PrivateKey, result.InitialMessage.EphemeralKey)
			require.NoError(t, err)
			dh3, err := signalcrypto.DH(signed.KeyPair.PrivateKey, result.InitialMessage.EphemeralKey)
			require.NoError(t, err)

			ikm := append(append([]byte{}, discontinuity...), dh1[:]...)
			ikm = append(ikm, dh2[:]...)
			ikm = append(ikm, dh3[:]...)
			if tt.includePre {
				dh4, err := signalcrypto.DH(pre.KeyPair.PrivateKey, result.InitialMessage.EphemeralKey)
				require.NoError(t, err)
				ikm = append(ikm, dh4[:]...)
			}
			kyberSS, err := signalcrypto.Kyber1024Decapsulate(kyber.KeyPair.PrivateKey, result.InitialMessage.KyberCiphertext)
			require.NoError(t, err)
			ikm = append(ikm, kyberSS...)
			expectedRoot, expectedChain, expectedPQR, err := derivePQSecret(ikm)
			require.NoError(t, err)
			require.Equal(t, expectedRoot, result.SharedSecret)
			require.Equal(t, expectedChain, *result.InitialChainKey)
			require.NotNil(t, result.PQRKey)
			require.Equal(t, expectedPQR, *result.PQRKey)
			require.Equal(t, AssociatedData(initID.PublicKey, respID.PublicKey), result.AssociatedData)
		})
	}
}

func TestInitiatorRejectsInvalidBundle(t *testing.T) {
	initID, _ := keys.GenerateIdentityKeyPair()
	respID, _ := keys.GenerateIdentityKeyPair()
	signed, _ := keys.GenerateSignedPreKey(respID, 1)
	kyber, _ := keys.GenerateKyberPreKey(respID, 12)
	bundle, _ := keys.NewPreKeyBundleWithKyber(1, 1, nil, signed, kyber, respID.PublicKey)

	// Tamper signature to force validation failure.
	bundle.SignedPreKeySignature[0] ^= 0xFF

	initiator := NewInitiator(initID)
	_, err := initiator.ProcessPreKeyBundle(bundle)
	require.Error(t, err)
}
