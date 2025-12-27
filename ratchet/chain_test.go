package ratchet

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKDFChainDeterministicAndDistinct(t *testing.T) {
	var chainKey [32]byte
	for i := range chainKey {
		chainKey[i] = byte(i)
	}
	newCK, mk := KDFChain(chainKey)

	require.Equal(t, "4304c22c84a53755ab08ead8d97a8d429be5efa480682d7ad1da27f73e1fbe1d", hex.EncodeToString(newCK[:]))
	require.Equal(t, "9b4c8120a4823a95f47cde17a244f4507244ee6e3957d1fab9fa29b44d3829b7", hex.EncodeToString(mk[:]))

	// Ensure second step changes outputs.
	newCK2, mk2 := KDFChain(newCK)
	require.NotEqual(t, newCK, newCK2)
	require.NotEqual(t, mk, mk2)
}

func TestDeriveMessageKeys(t *testing.T) {
	var mk [32]byte
	for i := range mk {
		mk[i] = 0x0f
	}
	enc, auth, iv := DeriveMessageKeys(mk)
	require.Equal(t, 32, len(enc))
	require.Equal(t, 32, len(auth))
	require.Equal(t, 16, len(iv))
	require.Equal(t, "b95813c5c7f97f334a62a6f360cc6ec08a26eecb5d5acd8326ff929ebf33378f", hex.EncodeToString(enc))
	require.Equal(t, "9c79e3278033b157e764a04fafd14c38f2d972bdaf7d0c420a64c189574d4e15", hex.EncodeToString(auth))
	require.Equal(t, "07f0996c3d506daef3577e16fd32928a", hex.EncodeToString(iv))
}
