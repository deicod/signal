package keys

import (
	"testing"

	signalerrors "github.com/deicod/signal/errors"
	"github.com/stretchr/testify/require"
)

func TestPreKeyBundleValidate(t *testing.T) {
	identity, err := GenerateIdentityKeyPair()
	require.NoError(t, err)

	pre, err := GeneratePreKey(10)
	require.NoError(t, err)

	signed, err := GenerateSignedPreKey(identity, 20)
	require.NoError(t, err)

	kyber, err := GenerateKyberPreKey(identity, 30)
	require.NoError(t, err)

	bundle, err := NewPreKeyBundleWithKyber(1234, 1, pre, signed, kyber, identity.PublicKey)
	require.NoError(t, err)
	require.NoError(t, bundle.Validate())
}

func TestPreKeyBundleValidationFailsOnSignature(t *testing.T) {
	identity, err := GenerateIdentityKeyPair()
	require.NoError(t, err)
	signed, err := GenerateSignedPreKey(identity, 20)
	require.NoError(t, err)

	kyber, err := GenerateKyberPreKey(identity, 30)
	require.NoError(t, err)

	bundle, err := NewPreKeyBundleWithKyber(1234, 1, nil, signed, kyber, identity.PublicKey)
	require.NoError(t, err)

	bundle.SignedPreKeySignature[0] ^= 0xFF
	require.ErrorIs(t, bundle.Validate(), signalerrors.ErrInvalidSignature)
}

func TestPreKeyBundleValidationFailsOnKyberSignature(t *testing.T) {
	identity, err := GenerateIdentityKeyPair()
	require.NoError(t, err)
	signed, err := GenerateSignedPreKey(identity, 20)
	require.NoError(t, err)
	kyber, err := GenerateKyberPreKey(identity, 30)
	require.NoError(t, err)

	bundle, err := NewPreKeyBundleWithKyber(1234, 1, nil, signed, kyber, identity.PublicKey)
	require.NoError(t, err)

	bundle.KyberPreKeySignature[0] ^= 0xFF
	require.ErrorIs(t, bundle.Validate(), signalerrors.ErrInvalidSignature)
}

func TestPreKeyBundleMissingFields(t *testing.T) {
	identity, _ := GenerateIdentityKeyPair()
	signed, _ := GenerateSignedPreKey(identity, 20)

	_, err := NewPreKeyBundle(1, 1, nil, nil, identity.PublicKey)
	require.Error(t, err)

	bundle, err := NewPreKeyBundle(1, 1, nil, signed, identity.PublicKey)
	require.NoError(t, err)

	// Only one of ID/key set -> invalid.
	idOnly := *bundle
	id := uint32(99)
	idOnly.PreKeyID = &id
	idOnly.PreKeyPublic = nil
	require.ErrorIs(t, idOnly.Validate(), signalerrors.ErrInvalidMessage)

	keyOnly := *bundle
	pub := signed.KeyPair.PublicKey
	keyOnly.PreKeyID = nil
	keyOnly.PreKeyPublic = &pub
	require.ErrorIs(t, keyOnly.Validate(), signalerrors.ErrInvalidMessage)

	kyber, _ := GenerateKyberPreKey(identity, 30)
	kyberBundle, err := NewPreKeyBundleWithKyber(1, 1, nil, signed, kyber, identity.PublicKey)
	require.NoError(t, err)
	kyberOnlyID := *kyberBundle
	kyberOnlyID.KyberPreKeyPublic = nil
	kyberOnlyID.KyberPreKeySignature = nil
	require.ErrorIs(t, kyberOnlyID.Validate(), signalerrors.ErrInvalidMessage)
}
