package session

import (
	"testing"

	"github.com/deicod/signal/keys"
	"github.com/deicod/signal/ratchet"
	"github.com/deicod/signal/store/memory"
	"github.com/deicod/signal/x3dh"
	"github.com/stretchr/testify/require"
)

func TestNewSessionInitializesFields(t *testing.T) {
	state, localID, remoteID := buildRatchetState(t)
	ad := []byte("metadata")

	sess, err := NewSession(state, localID, remoteID, ad)
	require.NoError(t, err)
	require.NotNil(t, sess.ratchetState)
	require.NotSame(t, state, sess.ratchetState)
	require.Equal(t, localID.PublicKey, sess.localIdentity.PublicKey)
	require.Equal(t, remoteID.PublicKey, sess.remoteIdentity.PublicKey)
	require.Equal(t, CurrentVersion, sess.Version())

	// Ensure associated data is copied.
	ad[0] ^= 0xFF
	require.Equal(t, []byte("metadata"), sess.AssociatedData())
}

func TestArchiveStateStoresPreviousAndLimits(t *testing.T) {
	state, localID, remoteID := buildRatchetState(t)
	sess, err := NewSession(state, localID, remoteID, nil)
	require.NoError(t, err)

	next := state.Clone()
	next.Ns = 7
	err = sess.ArchiveState(next, 2)
	require.NoError(t, err)
	require.Equal(t, uint32(7), sess.CurrentState().Ns)
	require.Len(t, sess.previousStates, 1)
	require.NotSame(t, state, sess.previousStates[0])

	third := next.Clone()
	third.Ns = 12
	err = sess.ArchiveState(third, 2)
	require.NoError(t, err)
	require.Equal(t, uint32(12), sess.CurrentState().Ns)
	require.Len(t, sess.previousStates, 2)

	fourth := third.Clone()
	fourth.Ns = 20
	err = sess.ArchiveState(fourth, 2)
	require.NoError(t, err)
	require.Equal(t, uint32(20), sess.CurrentState().Ns)
	require.Len(t, sess.previousStates, 2) // truncated to maxPrevious
}

func TestArchiveStateRejectsNil(t *testing.T) {
	state, localID, remoteID := buildRatchetState(t)
	sess, err := NewSession(state, localID, remoteID, nil)
	require.NoError(t, err)
	require.Error(t, sess.ArchiveState(nil, 1))
}

func TestVersionTracking(t *testing.T) {
	state, localID, remoteID := buildRatchetState(t)
	sess, err := NewSession(state, localID, remoteID, nil)
	require.NoError(t, err)
	require.Equal(t, CurrentVersion, sess.Version())
}

func buildRatchetState(tb testing.TB) (*ratchet.State, *keys.IdentityKey, *keys.IdentityKey) {
	tb.Helper()

	initID, _ := keys.GenerateIdentityKeyPair()
	respID, _ := keys.GenerateIdentityKeyPair()
	signed, _ := keys.GenerateSignedPreKey(respID, 10)
	pre, _ := keys.GeneratePreKey(11)

	bundle, err := keys.NewPreKeyBundle(1, 1, pre, signed, respID.PublicKey)
	require.NoError(tb, err)

	initRes, err := x3dh.NewInitiator(initID).ProcessPreKeyBundle(bundle)
	require.NoError(tb, err)

	store := memory.NewStore(respID, 1)
	require.NoError(tb, store.StorePreKey(pre.ID, pre))

	responder := x3dh.NewResponder(respID, signed, store)
	respRes, err := responder.ProcessInitialMessage(&initRes.InitialMessage)
	require.NoError(tb, err)

	state, err := ratchet.InitializeState(initRes, true)
	require.NoError(tb, err)

	// Wire up DHr for the initiator using responder info.
	state.DHr = &respRes.InitialMessage.EphemeralKey
	return state, &initID.PublicKey, &respID.PublicKey
}
