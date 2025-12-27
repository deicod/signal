package wire

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/deicod/signal/keys"
	"github.com/stretchr/testify/require"
)

func TestSignalMessageRoundTrip(t *testing.T) {
	macKey := bytes.Repeat([]byte{0xab}, 32)
	senderRatchet := mustHex32(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	senderIdentity := keys.IdentityKey{PublicKey: mustHex32(t, "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100")}
	receiverIdentity := keys.IdentityKey{PublicKey: mustHex32(t, "ffffffffeeeeeeeeddddddddccccccccbbbbbbbbaaaaaaaa9999999988888888")}
	ciphertext := []byte{0x01, 0x02, 0x03, 0x04}

	msg, err := NewSignalMessage(3, macKey, senderRatchet, 9, 8, ciphertext, senderIdentity, receiverIdentity, nil)
	require.NoError(t, err)

	parsed, err := ParseSignalMessage(msg.Serialize())
	require.NoError(t, err)
	require.Equal(t, msg.Counter(), parsed.Counter())
	require.Equal(t, msg.PreviousCounter(), parsed.PreviousCounter())
	require.Equal(t, msg.SenderRatchetKey(), parsed.SenderRatchetKey())
	require.Equal(t, msg.Ciphertext(), parsed.Ciphertext())

	ok, err := parsed.VerifyMAC(senderIdentity, receiverIdentity, macKey)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestPreKeySignalMessageRoundTrip(t *testing.T) {
	macKey := bytes.Repeat([]byte{0xcd}, 32)
	senderRatchet := mustHex32(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	senderIdentity := keys.IdentityKey{PublicKey: mustHex32(t, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")}
	receiverIdentity := keys.IdentityKey{PublicKey: mustHex32(t, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")}
	ciphertext := []byte("hello")

	signalMsg, err := NewSignalMessage(3, macKey, senderRatchet, 1, 0, ciphertext, senderIdentity, receiverIdentity, nil)
	require.NoError(t, err)

	registrationID := uint32(9)
	preKeyID := uint32(23)
	signedPreKeyID := uint32(802)
	baseKey := mustHex32(t, "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
	identityKey := keys.IdentityKey{PublicKey: mustHex32(t, "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")}

	preKeyMsg, err := NewPreKeySignalMessage(
		3,
		registrationID,
		&preKeyID,
		signedPreKeyID,
		nil,
		nil,
		baseKey,
		identityKey,
		signalMsg,
	)
	require.NoError(t, err)

	parsed, err := ParsePreKeySignalMessage(preKeyMsg.Serialize())
	require.NoError(t, err)
	require.Equal(t, preKeyMsg.Serialize(), parsed.Serialize())
}

func mustHex32(tb testing.TB, s string) [32]byte {
	tb.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(tb, err)
	if len(b) != 32 {
		tb.Fatalf("expected 32 bytes, got %d", len(b))
	}
	var out [32]byte
	copy(out[:], b)
	return out
}
