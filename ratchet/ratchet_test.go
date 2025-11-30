package ratchet

import (
	"fmt"
	"testing"

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
