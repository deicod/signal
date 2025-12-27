package ratchet

import (
	"fmt"
	"testing"

	signalerrors "github.com/deicod/signal/errors"
	"github.com/stretchr/testify/require"
)

func TestSimpleConversation(t *testing.T) {
	alice, bob, initRes, _ := buildTestStates(t)
	ad := initRes.AssociatedData

	msg1, err := alice.Encrypt([]byte("hi bob"), ad)
	require.NoError(t, err)
	pt1, err := bob.Decrypt(msg1, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("hi bob"), pt1)

	msg2, err := bob.Encrypt([]byte("hi alice"), ad)
	require.NoError(t, err)
	pt2, err := alice.Decrypt(msg2, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("hi alice"), pt2)
}

func TestOneSidedConversation(t *testing.T) {
	alice, bob, initRes, _ := buildTestStates(t)
	ad := initRes.AssociatedData

	var inbox []*Message
	for i := 0; i < 5; i++ {
		msg, err := alice.Encrypt([]byte(fmt.Sprintf("msg-%d", i)), ad)
		require.NoError(t, err)
		inbox = append(inbox, msg)
	}

	for i, m := range inbox {
		pt, err := bob.Decrypt(m, ad)
		require.NoError(t, err)
		require.Equal(t, []byte(fmt.Sprintf("msg-%d", i)), pt)
	}
}

func TestOutOfOrderDelivery(t *testing.T) {
	alice, bob, initRes, _ := buildTestStates(t)
	ad := initRes.AssociatedData

	msg1, _ := alice.Encrypt([]byte("one"), ad)
	msg2, _ := alice.Encrypt([]byte("two"), ad)
	msg3, _ := alice.Encrypt([]byte("three"), ad)

	// Deliver out of order: 3,1,2
	pt, err := bob.Decrypt(msg3, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("three"), pt)

	pt, err = bob.Decrypt(msg1, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("one"), pt)

	pt, err = bob.Decrypt(msg2, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("two"), pt)
}

func TestOutOfOrderAcrossRatchetStep(t *testing.T) {
	alice, bob, initRes, _ := buildTestStates(t)
	ad := initRes.AssociatedData

	old1, err := alice.Encrypt([]byte("old-1"), ad)
	require.NoError(t, err)
	old2, err := alice.Encrypt([]byte("old-2"), ad)
	require.NoError(t, err)

	// Deliver one old-chain message so Bob ratchets to Alice's current DH.
	pt, err := bob.Decrypt(old1, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("old-1"), pt)

	// Bob sends a message that triggers a DH ratchet when Alice receives it.
	bobMsg, err := bob.Encrypt([]byte("bob-1"), ad)
	require.NoError(t, err)
	plain, err := alice.Decrypt(bobMsg, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("bob-1"), plain)

	// Alice now sends with a new DH.
	new1, err := alice.Encrypt([]byte("new-1"), ad)
	require.NoError(t, err)

	// Deliver out of order: new chain message first, then old chain messages.
	pt, err = bob.Decrypt(new1, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("new-1"), pt)

	_, err = bob.Decrypt(old2, ad)
	require.ErrorIs(t, err, signalerrors.ErrDuplicateMessage)
}

func TestDuplicateMessageRejected(t *testing.T) {
	alice, bob, initRes, _ := buildTestStates(t)
	ad := initRes.AssociatedData

	msg, err := alice.Encrypt([]byte("hi bob"), ad)
	require.NoError(t, err)

	pt, err := bob.Decrypt(msg, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("hi bob"), pt)

	_, err = bob.Decrypt(msg, ad)
	require.Error(t, err)
	require.ErrorIs(t, err, signalerrors.ErrDuplicateMessage)
}

func TestOldChainMessageRejectedAfterRatchet(t *testing.T) {
	alice, bob, initRes, _ := buildTestStates(t)
	ad := initRes.AssociatedData

	old1, err := alice.Encrypt([]byte("old-1"), ad)
	require.NoError(t, err)
	old2, err := alice.Encrypt([]byte("old-2"), ad)
	require.NoError(t, err)

	// Deliver one old-chain message so Bob ratchets to Alice's current DH.
	pt, err := bob.Decrypt(old1, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("old-1"), pt)

	// Trigger a ratchet and deliver the new-chain message first so Bob stores skipped keys.
	bobMsg, err := bob.Encrypt([]byte("bob-1"), ad)
	require.NoError(t, err)
	_, err = alice.Decrypt(bobMsg, ad)
	require.NoError(t, err)

	new1, err := alice.Encrypt([]byte("new-1"), ad)
	require.NoError(t, err)
	_, err = bob.Decrypt(new1, ad)
	require.NoError(t, err)

	_, err = bob.Decrypt(old2, ad)
	require.ErrorIs(t, err, signalerrors.ErrDuplicateMessage)
}

func TestMessageLossAndRecovery(t *testing.T) {
	alice, bob, initRes, _ := buildTestStates(t)
	ad := initRes.AssociatedData

	msg1, _ := alice.Encrypt([]byte("keep-1"), ad)
	_, _ = alice.Encrypt([]byte("drop"), ad)
	msg3, _ := alice.Encrypt([]byte("keep-2"), ad)

	pt, err := bob.Decrypt(msg1, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("keep-1"), pt)

	// drop msg2
	pt, err = bob.Decrypt(msg3, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("keep-2"), pt)
}

func TestMaxSkipLimit(t *testing.T) {
	alice, bob, initRes, _ := buildTestStates(t)
	ad := initRes.AssociatedData

	var last *Message
	for i := 0; i < MaxSkip+5; i++ {
		msg, err := alice.Encrypt([]byte(fmt.Sprintf("bulk-%d", i)), ad)
		require.NoError(t, err)
		last = msg
	}

	_, err := bob.Decrypt(last, ad)
	require.Error(t, err)
}

func BenchmarkEncryptDecrypt(b *testing.B) {
	alice, bob, initRes, _ := buildTestStates(b)
	ad := initRes.AssociatedData
	payload := []byte("benchmark")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		msg, err := alice.Encrypt(payload, ad)
		if err != nil {
			b.Fatalf("encrypt: %v", err)
		}
		if _, err := bob.Decrypt(msg, ad); err != nil {
			b.Fatalf("decrypt: %v", err)
		}
	}
}

func FuzzDoubleRatchetRoundTrip(f *testing.F) {
	f.Add(uint(2), uint(2))
	f.Fuzz(func(t *testing.T, aCount uint, bCount uint) {
		alice, bob, initRes, _ := buildTestStates(t)
		ad := initRes.AssociatedData

		for i := 0; i < int(aCount%5)+1; i++ {
			msg, err := alice.Encrypt([]byte(fmt.Sprintf("a-%d", i)), ad)
			if err != nil {
				t.Fatalf("encrypt alice: %v", err)
			}
			if _, err := bob.Decrypt(msg, ad); err != nil {
				t.Fatalf("decrypt bob: %v", err)
			}
		}

		for j := 0; j < int(bCount%5)+1; j++ {
			msg, err := bob.Encrypt([]byte(fmt.Sprintf("b-%d", j)), ad)
			if err != nil {
				t.Fatalf("encrypt bob: %v", err)
			}
			if _, err := alice.Decrypt(msg, ad); err != nil {
				t.Fatalf("decrypt alice: %v", err)
			}
		}
	})
}
