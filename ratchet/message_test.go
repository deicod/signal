package ratchet

import (
	"testing"

	"github.com/deicod/signal/x3dh"
	"github.com/stretchr/testify/require"
)

func TestEncryptDecryptFlow(t *testing.T) {
	x3res := dummyX3DHResult(t)
	sendState, _ := InitializeState(x3res, true)
	recvState, _ := InitializeState(x3res, false)
	recvState.DHr = &sendState.DHs.PublicKey

	ad := []byte("ad")
	msg, err := sendState.Encrypt([]byte("hello"), ad)
	require.NoError(t, err)

	pt, err := recvState.Decrypt(msg, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), pt)
}

func TestDecryptWithSkippedMessages(t *testing.T) {
	x3res := dummyX3DHResult(t)
	sendState, _ := InitializeState(x3res, true)
	recvState, _ := InitializeState(x3res, false)
	recvState.DHr = &sendState.DHs.PublicKey

	ad := []byte("ad")
	// Send two messages, drop the first at receiver, then process out of order.
	msg1, _ := sendState.Encrypt([]byte("one"), ad)
	msg2, _ := sendState.Encrypt([]byte("two"), ad)

	pt2, err := recvState.Decrypt(msg2, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("two"), pt2)

	pt1, err := recvState.Decrypt(msg1, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("one"), pt1)
}

func dummyX3DHResult(t *testing.T) *x3dh.Result {
	t.Helper()
	shared := mustHex32(t, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	initMsg := x3dh.Message{EphemeralKey: mustHex32(t, "abababababababababababababababababababababababababababababababab")}
	return &x3dh.Result{
		SharedSecret:   shared,
		AssociatedData: []byte("ad"),
		InitialMessage: initMsg,
	}
}
