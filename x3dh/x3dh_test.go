package x3dh

import (
	"testing"

	"github.com/deicod/signal/keys"
	"github.com/deicod/signal/store/memory"
	"github.com/stretchr/testify/require"
)

func TestX3DHCompleteHandshake(t *testing.T) {
	runHandshakeScenario(t, true)
	runHandshakeScenario(t, false)
}

func runHandshakeScenario(t *testing.T, withPreKey bool) {
	t.Helper()
	initID, _ := keys.GenerateIdentityKeyPair()
	respID, _ := keys.GenerateIdentityKeyPair()
	signed, _ := keys.GenerateSignedPreKey(respID, 10)
	var pre *keys.PreKey
	if withPreKey {
		pre, _ = keys.GeneratePreKey(11)
	}

	bundle, _ := keys.NewPreKeyBundle(1, 1, pre, signed, respID.PublicKey)
	initiator := NewInitiator(initID)
	initResult, err := initiator.ProcessPreKeyBundle(bundle)
	require.NoError(t, err)

	store := memory.NewStore(respID, 1)
	if pre != nil {
		require.NoError(t, store.StorePreKey(pre.ID, pre))
	}
	responder := NewResponder(respID, signed, store)
	respResult, err := responder.ProcessInitialMessage(&initResult.InitialMessage)
	require.NoError(t, err)

	require.Equal(t, initResult.SharedSecret, respResult.SharedSecret)
	require.Equal(t, initResult.AssociatedData, respResult.AssociatedData)
}

func TestX3DHInvalidSignedPreKey(t *testing.T) {
	initID, _ := keys.GenerateIdentityKeyPair()
	respID, _ := keys.GenerateIdentityKeyPair()
	signed, _ := keys.GenerateSignedPreKey(respID, 10)
	bundle, _ := keys.NewPreKeyBundle(1, 1, nil, signed, respID.PublicKey)

	// Tamper signature
	bundle.SignedPreKeySignature[0] ^= 0xFF
	_, err := NewInitiator(initID).ProcessPreKeyBundle(bundle)
	require.Error(t, err)
}

func TestX3DHReplayPreKeyUse(t *testing.T) {
	initID, _ := keys.GenerateIdentityKeyPair()
	respID, _ := keys.GenerateIdentityKeyPair()
	signed, _ := keys.GenerateSignedPreKey(respID, 10)
	pre, _ := keys.GeneratePreKey(11)
	bundle, _ := keys.NewPreKeyBundle(1, 1, pre, signed, respID.PublicKey)

	initiator := NewInitiator(initID)
	initResult, _ := initiator.ProcessPreKeyBundle(bundle)

	store := memory.NewStore(respID, 1)
	_ = store.StorePreKey(pre.ID, pre)

	responder := NewResponder(respID, signed, store)
	_, err := responder.ProcessInitialMessage(&initResult.InitialMessage)
	require.NoError(t, err)

	// Replay same initial message should fail due to missing one-time pre-key.
	_, err = responder.ProcessInitialMessage(&initResult.InitialMessage)
	require.Error(t, err)
}

func FuzzX3DHHandshake(f *testing.F) {
	f.Add(true)
	f.Add(false)
	f.Fuzz(func(t *testing.T, withPreKey bool) {
		initID, _ := keys.GenerateIdentityKeyPair()
		respID, _ := keys.GenerateIdentityKeyPair()
		signed, _ := keys.GenerateSignedPreKey(respID, 5)
		var pre *keys.PreKey
		if withPreKey {
			pre, _ = keys.GeneratePreKey(9)
		}
		bundle, err := keys.NewPreKeyBundle(1, 1, pre, signed, respID.PublicKey)
		if err != nil {
			t.Skip()
		}
		initiator := NewInitiator(initID)
		initRes, err := initiator.ProcessPreKeyBundle(bundle)
		if err != nil {
			t.Skip()
		}
		store := memory.NewStore(respID, 1)
		if pre != nil {
			_ = store.StorePreKey(pre.ID, pre)
		}
		responder := NewResponder(respID, signed, store)
		respRes, err := responder.ProcessInitialMessage(&initRes.InitialMessage)
		if err != nil {
			return
		}
		if initRes.SharedSecret != respRes.SharedSecret {
			t.Fatalf("shared secret mismatch")
		}
	})
}

func BenchmarkX3DHHandshake(b *testing.B) {
	initID, _ := keys.GenerateIdentityKeyPair()
	respID, _ := keys.GenerateIdentityKeyPair()
	signed, _ := keys.GenerateSignedPreKey(respID, 5)
	pre, _ := keys.GeneratePreKey(9)
	bundle, _ := keys.NewPreKeyBundle(1, 1, pre, signed, respID.PublicKey)
	store := memory.NewStore(respID, 1)
	_ = store.StorePreKey(pre.ID, pre)

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// Fresh initiator/ephemeral each loop to exercise full cost.
		initiator := NewInitiator(initID)
		initRes, err := initiator.ProcessPreKeyBundle(bundle)
		if err != nil {
			b.Fatalf("initiator error: %v", err)
		}
		responder := NewResponder(respID, signed, store)
		if _, err := responder.ProcessInitialMessage(&initRes.InitialMessage); err != nil {
			b.Fatalf("responder error: %v", err)
		}
	}
}
