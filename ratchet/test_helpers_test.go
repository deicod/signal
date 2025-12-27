package ratchet

import (
	"testing"

	"github.com/deicod/signal/keys"
	"github.com/deicod/signal/store/memory"
	"github.com/deicod/signal/x3dh"
	"github.com/stretchr/testify/require"
)

// buildTestStates performs an X3DH handshake and initializes ratchet states for both parties.
func buildTestStates(tb testing.TB) (*State, *State, *x3dh.Result, *x3dh.Result) {
	tb.Helper()

	initID, _ := keys.GenerateIdentityKeyPair()
	respID, _ := keys.GenerateIdentityKeyPair()
	signed, _ := keys.GenerateSignedPreKey(respID, 10)
	pre, _ := keys.GeneratePreKey(11)
	kyber, _ := keys.GenerateKyberPreKey(respID, 12)

	bundle, err := keys.NewPreKeyBundleWithKyber(1, 1, pre, signed, kyber, respID.PublicKey)
	require.NoError(tb, err)

	initiator := x3dh.NewInitiator(initID)
	initRes, err := initiator.ProcessPreKeyBundle(bundle)
	require.NoError(tb, err)

	store := memory.NewStore(respID, 1)
	require.NoError(tb, store.StorePreKey(pre.ID, pre))
	require.NoError(tb, store.StoreKyberPreKey(kyber.ID, kyber))

	responder := x3dh.NewResponder(respID, signed, store, store)
	respRes, err := responder.ProcessInitialMessage(&initRes.InitialMessage)
	require.NoError(tb, err)

	initState, err := InitializeState(initRes, true)
	require.NoError(tb, err)

	respState, err := InitializeState(respRes, false)
	require.NoError(tb, err)

	return initState, respState, initRes, respRes
}
