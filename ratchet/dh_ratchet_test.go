package ratchet

import (
	"testing"

	"github.com/deicod/signal/crypto"
	"github.com/stretchr/testify/require"
)

func TestKDFRootProducesDistinctKeys(t *testing.T) {
	var rk [32]byte
	var dh [32]byte
	for i := 0; i < 32; i++ {
		rk[i] = byte(i)
		dh[i] = byte(255 - i)
	}
	newRK, ck, err := KDFRoot(rk, dh)
	require.NoError(t, err)
	require.NotEqual(t, rk, newRK)
	require.NotZero(t, ck)
}

func TestDHRatchetUpdatesKeysAndCounters(t *testing.T) {
	state, _, _, _ := buildTestStates(t)

	their, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	state.Ns = 5
	state.Nr = 3

	err = state.DHRatchet(their.PublicKey)
	require.NoError(t, err)

	require.Equal(t, uint32(5), state.PN)
	require.Equal(t, uint32(0), state.Ns)
	require.Equal(t, uint32(0), state.Nr)
	require.NotNil(t, state.DHs)
	require.NotNil(t, state.DHr)
	require.Equal(t, their.PublicKey, *state.DHr)
	require.NotZero(t, state.CKs)
	require.NotZero(t, state.CKr)
}
