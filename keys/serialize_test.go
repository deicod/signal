package keys

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIdentityKeySerializeRoundTrip(t *testing.T) {
	ik, err := GenerateIdentityKeyPair()
	require.NoError(t, err)

	enc, err := ik.PublicKey.Serialize()
	require.NoError(t, err)

	decoded, err := DeserializeIdentityKey(enc)
	require.NoError(t, err)
	require.Equal(t, ik.PublicKey, *decoded)
}

func TestPreKeySerializeRoundTrip(t *testing.T) {
	pk, err := GeneratePreKey(7)
	require.NoError(t, err)

	enc, err := pk.Serialize()
	require.NoError(t, err)

	decoded, err := DeserializePreKey(enc)
	require.NoError(t, err)
	require.Equal(t, pk.ID, decoded.ID)
	require.Equal(t, pk.KeyPair.PublicKey, decoded.KeyPair.PublicKey)
}

func TestSignedPreKeySerializeRoundTrip(t *testing.T) {
	id, _ := GenerateIdentityKeyPair()
	spk, err := GenerateSignedPreKey(id, 8)
	require.NoError(t, err)

	enc, err := spk.Serialize()
	require.NoError(t, err)

	decoded, err := DeserializeSignedPreKey(enc)
	require.NoError(t, err)
	require.Equal(t, spk.ID, decoded.ID)
	require.Equal(t, spk.KeyPair.PublicKey, decoded.KeyPair.PublicKey)
	require.Equal(t, spk.Signature, decoded.Signature)
}

func TestBundleSerializeRoundTrip(t *testing.T) {
	identity, _ := GenerateIdentityKeyPair()
	pre, _ := GeneratePreKey(10)
	signed, _ := GenerateSignedPreKey(identity, 20)

	bundle, err := NewPreKeyBundle(1234, 2, pre, signed, identity.PublicKey)
	require.NoError(t, err)

	enc, err := bundle.Serialize()
	require.NoError(t, err)

	decoded, err := DeserializePreKeyBundle(enc)
	require.NoError(t, err)
	require.Equal(t, bundle.RegistrationID, decoded.RegistrationID)
	require.Equal(t, bundle.DeviceID, decoded.DeviceID)
	require.NotNil(t, decoded.PreKeyID)
	require.Equal(t, *bundle.PreKeyID, *decoded.PreKeyID)
	require.Equal(t, *bundle.PreKeyPublic, *decoded.PreKeyPublic)
	require.Equal(t, bundle.SignedPreKeyID, decoded.SignedPreKeyID)
	require.Equal(t, bundle.SignedPreKeyPublic, decoded.SignedPreKeyPublic)
	require.Equal(t, bundle.SignedPreKeySignature, decoded.SignedPreKeySignature)
	require.Equal(t, bundle.IdentityKey, decoded.IdentityKey)
}

func TestDeserializeErrors(t *testing.T) {
	_, err := DeserializeIdentityKey([]byte{0})
	require.Error(t, err)

	badVersion := make([]byte, 65)
	badVersion[0] = 2
	_, err = DeserializeIdentityKey(badVersion)
	require.Error(t, err)

	_, err = DeserializePreKey([]byte{0, 1, 2})
	require.Error(t, err)

	_, err = DeserializeSignedPreKey([]byte{0, 1, 2})
	require.Error(t, err)

	_, err = DeserializePreKeyBundle([]byte{0, 1, 2})
	require.Error(t, err)
}
