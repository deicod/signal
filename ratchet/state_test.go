package ratchet

import (
	"encoding/hex"
	"testing"

	"github.com/deicod/signal/x3dh"
	"github.com/stretchr/testify/require"
)

func TestInitializeStateFromX3DHInitiator(t *testing.T) {
	alice, _, _, _ := buildTestStates(t)
	require.NotNil(t, alice.DHs)
	require.NotNil(t, alice.DHr)
	require.NotZero(t, alice.RK)
	require.NotZero(t, alice.CKs)
	require.Zero(t, alice.CKr)
}

func TestInitializeStateFromX3DHResponder(t *testing.T) {
	_, bob, _, respRes := buildTestStates(t)
	require.NotNil(t, bob.DHs)
	require.NotNil(t, bob.DHr)
	require.Equal(t, respRes.InitialMessage.EphemeralKey, *bob.DHr)
	require.NotZero(t, bob.CKr)
	require.NotZero(t, bob.CKs)
}

func TestInitializeStateRejectsInvalidSharedSecret(t *testing.T) {
	_, err := InitializeState(&x3dh.Result{SharedSecret: [32]byte{}}, true)
	require.Error(t, err)
}

func TestCloneMakesDeepCopy(t *testing.T) {
	state, _, _, _ := buildTestStates(t)
	state.MKSkipped[SkippedKey{N: 1}] = mustHex32(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	clone := state.Clone()
	require.Equal(t, state.MKSkipped, clone.MKSkipped)

	clone.MKSkipped[SkippedKey{N: 2}] = mustHex32(t, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	require.NotEqual(t, state.MKSkipped, clone.MKSkipped)
}

func TestRatchetOnSendUsesDHr(t *testing.T) {
	state, _, _, _ := buildTestStates(t)
	err := state.RatchetOnSend()
	require.NoError(t, err)
	require.NotZero(t, state.CKs)
}

func mustHex32(tb testing.TB, s string) [32]byte {
	tb.Helper()
	var out [32]byte
	decoded, err := hexStringToBytes(s)
	require.NoError(tb, err)
	copy(out[:], decoded)
	return out
}

func hexStringToBytes(s string) ([]byte, error) {
	dst := make([]byte, len(s)/2)
	_, err := hex.Decode(dst, []byte(s))
	return dst, err
}
