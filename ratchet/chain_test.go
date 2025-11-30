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
	require.Equal(t, "a65e0fec3289690396f94cf6afbd96f505b670b2e0199e501e371aebbf61cf9b", hex.EncodeToString(enc))
	require.Equal(t, "596038f20154dc71b377768095ba2886edafd62aa86b2701db58e017613a1b33", hex.EncodeToString(auth))
	require.Equal(t, "de40a4630dbb0df974a7b600c10fbfbe", hex.EncodeToString(iv))
}
