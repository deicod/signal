package session

import (
	"testing"

	"github.com/deicod/signal/keys"
	"github.com/deicod/signal/ratchet"
	"github.com/deicod/signal/store/memory"
	"github.com/deicod/signal/x3dh"
	"github.com/stretchr/testify/require"
)

func buildRatchetState(tb testing.TB) (*ratchet.State, *keys.IdentityKey, *keys.IdentityKey) {
	tb.Helper()

	initID, _ := keys.GenerateIdentityKeyPair()
	respID, _ := keys.GenerateIdentityKeyPair()
	signed, _ := keys.GenerateSignedPreKey(respID, 10)
	pre, _ := keys.GeneratePreKey(11)
	kyber, _ := keys.GenerateKyberPreKey(respID, 12)

	bundle, err := keys.NewPreKeyBundleWithKyber(1, 1, pre, signed, kyber, respID.PublicKey)
	require.NoError(tb, err)

	initRes, err := x3dh.NewInitiator(initID).ProcessPreKeyBundle(bundle)
	require.NoError(tb, err)

	store := memory.NewStore(respID, 1)
	require.NoError(tb, store.StorePreKey(pre.ID, pre))
	require.NoError(tb, store.StoreKyberPreKey(kyber.ID, kyber))

	responder := x3dh.NewResponder(respID, signed, store, store)
	respRes, err := responder.ProcessInitialMessage(&initRes.InitialMessage)
	require.NoError(tb, err)

	state, err := ratchet.InitializeState(initRes, true)
	require.NoError(tb, err)

	// Wire up DHr for the initiator using responder info.
	state.DHr = &respRes.InitialMessage.EphemeralKey
	return state, &initID.PublicKey, &respID.PublicKey
}
