package keys

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGeneratePreKey(t *testing.T) {
	pk, err := GeneratePreKey(1)
	require.NoError(t, err)
	require.Equal(t, uint32(1), pk.ID)
	require.NotNil(t, pk.KeyPair)
	require.NotZero(t, pk.Timestamp)
}

func TestGeneratePreKeysSequential(t *testing.T) {
	keys, err := GeneratePreKeys(5, 3)
	require.NoError(t, err)
	require.Len(t, keys, 3)
	require.Equal(t, uint32(5), keys[0].ID)
	require.Equal(t, uint32(6), keys[1].ID)
	require.Equal(t, uint32(7), keys[2].ID)
}

func TestGeneratePreKeysZeroCount(t *testing.T) {
	keys, err := GeneratePreKeys(10, 0)
	require.NoError(t, err)
	require.Len(t, keys, 0)
}

func TestGenerateSignedPreKeyAndVerify(t *testing.T) {
	identity, err := GenerateIdentityKeyPair()
	require.NoError(t, err)

	spk, err := GenerateSignedPreKey(identity, 42)
	require.NoError(t, err)
	require.Equal(t, uint32(42), spk.ID)
	require.NotNil(t, spk.KeyPair)
	require.NotZero(t, spk.Timestamp)
	require.True(t, spk.VerifySignedPreKey(&identity.PublicKey))

	// Tamper signature
	bad := append([]byte{}, spk.Signature...)
	bad[0] ^= 0xFF
	spk.Signature = bad
	require.False(t, spk.VerifySignedPreKey(&identity.PublicKey))
}

func TestGenerateSignedPreKeyNilIdentity(t *testing.T) {
	_, err := GenerateSignedPreKey(nil, 1)
	require.Error(t, err)
}

func TestGeneratePreKeysNegativeCount(t *testing.T) {
	_, err := GeneratePreKeys(1, -1)
	require.Error(t, err)
}

func TestPreKeyTimestampsAreUTC(t *testing.T) {
	pk, err := GeneratePreKey(1)
	require.NoError(t, err)
	require.Equal(t, pk.Timestamp.UTC(), pk.Timestamp)

	identity, _ := GenerateIdentityKeyPair()
	spk, err := GenerateSignedPreKey(identity, 2)
	require.NoError(t, err)
	require.Equal(t, spk.Timestamp.UTC(), spk.Timestamp)
}
