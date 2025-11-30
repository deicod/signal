package ratchet

import (
	"testing"

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
