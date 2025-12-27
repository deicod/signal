package ratchet

import (
	"testing"

	signalcrypto "github.com/deicod/signal/crypto"
	"github.com/stretchr/testify/require"
)

func TestStateSerializeRoundTripAndDeterminism(t *testing.T) {
	var dhs signalcrypto.KeyPair
	for i := range dhs.PublicKey {
		dhs.PublicKey[i] = byte(i + 1)
		dhs.PrivateKey[i] = byte(100 + i)
	}
	var dhr [32]byte
	for i := range dhr {
		dhr[i] = byte(200 + i)
	}

	state := &State{
		DHs: &dhs,
		DHr: &dhr,
		Ns:  5,
		Nr:  7,
		PN:  3,
		MKSkipped: map[SkippedKey][32]byte{
			{PublicKey: [32]byte{2}, N: 1}: {9},
			{PublicKey: [32]byte{1}, N: 2}: {8},
		},
		SeenDH: map[[32]byte]struct{}{
			{3}: {},
			{4}: {},
		},
	}
	state.RK[0] = 0x10
	state.CKs[0] = 0x20
	state.CKr[0] = 0x30

	wire1, err := state.Serialize()
	require.NoError(t, err)
	wire2, err := state.Serialize()
	require.NoError(t, err)
	require.Equal(t, wire1, wire2)

	decoded, err := DeserializeState(wire1)
	require.NoError(t, err)
	require.NotNil(t, decoded.DHs)
	require.NotNil(t, decoded.DHr)
	require.Equal(t, *state.DHs, *decoded.DHs)
	require.Equal(t, *state.DHr, *decoded.DHr)
	require.Equal(t, state.RK, decoded.RK)
	require.Equal(t, state.CKs, decoded.CKs)
	require.Equal(t, state.CKr, decoded.CKr)
	require.Equal(t, state.Ns, decoded.Ns)
	require.Equal(t, state.Nr, decoded.Nr)
	require.Equal(t, state.PN, decoded.PN)
	require.Equal(t, state.MKSkipped, decoded.MKSkipped)
	require.Equal(t, state.SeenDH, decoded.SeenDH)

	wire3, err := decoded.Serialize()
	require.NoError(t, err)
	require.Equal(t, wire1, wire3)
}
