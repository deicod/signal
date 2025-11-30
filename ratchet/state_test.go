package ratchet

import (
	"encoding/hex"
	"testing"

	"github.com/deicod/signal/keys"
	"github.com/deicod/signal/x3dh"
	"github.com/stretchr/testify/require"
)

func TestInitializeStateFromX3DHInitiator(t *testing.T) {
	x3 := dummyX3DHResult(t)
	state, err := InitializeState(x3, true)
	require.NoError(t, err)
	require.NotNil(t, state.DHs)
	require.Nil(t, state.DHr)
	require.NotZero(t, state.RK)
	require.NotZero(t, state.CKs)
	require.Zero(t, state.CKr)
}

func TestInitializeStateFromX3DHResponder(t *testing.T) {
	x3 := dummyX3DHResult(t)
	state, err := InitializeState(x3, false)
	require.NoError(t, err)
	require.Nil(t, state.DHs)
	require.NotNil(t, state.DHr)
	require.Equal(t, x3.InitialMessage.EphemeralKey, *state.DHr)
}

func TestInitializeStateRejectsInvalidSharedSecret(t *testing.T) {
	_, err := InitializeState(&x3dh.Result{SharedSecret: [32]byte{}}, true)
	require.NoError(t, err)
}

func TestCloneMakesDeepCopy(t *testing.T) {
	x3 := dummyX3DHResult(t)
	state, _ := InitializeState(x3, true)
	state.MKSkipped[SkippedKey{N: 1}] = mustHex32(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	clone := state.Clone()
	require.Equal(t, state.MKSkipped, clone.MKSkipped)

	clone.MKSkipped[SkippedKey{N: 2}] = mustHex32(t, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	require.NotEqual(t, state.MKSkipped, clone.MKSkipped)
}

func TestRatchetOnSendUsesDHr(t *testing.T) {
	x3 := dummyX3DHResult(t)
	state, _ := InitializeState(x3, true)
	their := mustHex32(t, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	state.DHr = &their

	err := state.RatchetOnSend()
	require.NoError(t, err)
	require.NotNil(t, state.DHs)
	require.NotZero(t, state.CKs)
}

func dummyX3DHResult(t *testing.T) *x3dh.Result {
	t.Helper()
	curveKey := mustHex32(t, "0102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff")
	initMsg := x3dh.Message{EphemeralKey: curveKey}
	return &x3dh.Result{
		SharedSecret:   mustHex32(t, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"),
		AssociatedData: []byte("ad"),
		RemoteIdentity: keys.IdentityKey{},
		InitialMessage: initMsg,
	}
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
