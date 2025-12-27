package ratchet

import (
	"testing"

	signalerrors "github.com/deicod/signal/errors"
	"github.com/stretchr/testify/require"
)

func TestEncryptDecryptFlow(t *testing.T) {
	alice, bob, initRes, _ := buildTestStates(t)

	ad := initRes.AssociatedData
	msg, err := alice.Encrypt([]byte("hello"), ad)
	require.NoError(t, err)

	pt, err := bob.Decrypt(msg, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), pt)
}

func TestDecryptWithSkippedMessages(t *testing.T) {
	alice, bob, initRes, _ := buildTestStates(t)

	ad := initRes.AssociatedData
	// Send two messages, drop the first at receiver, then process out of order.
	msg1, _ := alice.Encrypt([]byte("one"), ad)
	msg2, _ := alice.Encrypt([]byte("two"), ad)

	pt2, err := bob.Decrypt(msg2, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("two"), pt2)

	pt1, err := bob.Decrypt(msg1, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("one"), pt1)
}

func TestDecryptInvalidMACDoesNotAdvanceState(t *testing.T) {
	alice, bob, initRes, _ := buildTestStates(t)

	ad := initRes.AssociatedData
	msg, err := alice.Encrypt([]byte("hello"), ad)
	require.NoError(t, err)

	tampered := &Message{
		Header:     msg.Header,
		Ciphertext: append([]byte(nil), msg.Ciphertext...),
	}
	tampered.Ciphertext[15] ^= 0x01

	_, err = bob.Decrypt(tampered, ad)
	require.Error(t, err)
	require.ErrorIs(t, err, signalerrors.ErrInvalidMAC)

	pt, err := bob.Decrypt(msg, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), pt)
}

func TestSkippedKeyNotConsumedOnInvalidMAC(t *testing.T) {
	alice, bob, initRes, _ := buildTestStates(t)

	ad := initRes.AssociatedData
	msg1, err := alice.Encrypt([]byte("one"), ad)
	require.NoError(t, err)
	msg2, err := alice.Encrypt([]byte("two"), ad)
	require.NoError(t, err)

	pt2, err := bob.Decrypt(msg2, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("two"), pt2)

	tampered1 := &Message{
		Header:     msg1.Header,
		Ciphertext: append([]byte(nil), msg1.Ciphertext...),
	}
	tampered1.Ciphertext[18] ^= 0x01

	_, err = bob.Decrypt(tampered1, ad)
	require.Error(t, err)
	require.ErrorIs(t, err, signalerrors.ErrInvalidMAC)

	pt1, err := bob.Decrypt(msg1, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("one"), pt1)
}
