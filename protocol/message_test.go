package protocol

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/deicod/signal/keys"
	"github.com/stretchr/testify/require"
)

func TestSignalMessageSerializeRoundTrip(t *testing.T) {
	macKey := bytes.Repeat([]byte{0x11}, 32)
	senderRatchet := mustHex32(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	senderIdentity := keys.IdentityKey{PublicKey: mustHex32(t, "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100")}
	receiverIdentity := keys.IdentityKey{PublicKey: mustHex32(t, "ffffffffeeeeeeeeddddddddccccccccbbbbbbbbaaaaaaaa9999999988888888")}
	ciphertext := []byte("cipher")

	msg, err := NewSignalMessage(3, macKey, senderRatchet, 10, 2, ciphertext, senderIdentity, receiverIdentity, nil)
	require.NoError(t, err)

	enc := msg.Serialize()
	dec, err := ParseSignalMessage(enc)
	require.NoError(t, err)
	require.Equal(t, msg.MessageVersion(), dec.MessageVersion())
	require.Equal(t, msg.SenderRatchetKey(), dec.SenderRatchetKey())
	require.Equal(t, msg.Counter(), dec.Counter())
	require.Equal(t, msg.PreviousCounter(), dec.PreviousCounter())
	require.Equal(t, msg.Ciphertext(), dec.Ciphertext())

	ok, err := dec.VerifyMAC(senderIdentity, receiverIdentity, macKey)
	require.NoError(t, err)
	require.True(t, ok)

	tampered := dec.Serialize()
	tampered[len(tampered)-1] ^= 0xff
	tamperedMsg, err := ParseSignalMessage(tampered)
	require.NoError(t, err)
	ok, err = tamperedMsg.VerifyMAC(senderIdentity, receiverIdentity, macKey)
	require.NoError(t, err)
	require.False(t, ok)
}

func TestPreKeyMessageSerializeRoundTrip(t *testing.T) {
	macKey := bytes.Repeat([]byte{0x22}, 32)
	senderRatchet := mustHex32(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	senderIdentity := keys.IdentityKey{PublicKey: mustHex32(t, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")}
	receiverIdentity := keys.IdentityKey{PublicKey: mustHex32(t, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")}
	ciphertext := []byte("cipher")

	signalMsg, err := NewSignalMessage(3, macKey, senderRatchet, 1, 0, ciphertext, senderIdentity, receiverIdentity, nil)
	require.NoError(t, err)

	registrationID := uint32(5)
	preKeyID := uint32(7)
	signedPreKeyID := uint32(9)
	baseKey := mustHex32(t, "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
	identityKey := keys.IdentityKey{PublicKey: mustHex32(t, "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")}

	msg, err := NewPreKeyMessage(3, registrationID, &preKeyID, signedPreKeyID, nil, nil, baseKey, identityKey, signalMsg)
	require.NoError(t, err)

	enc := msg.Serialize()
	dec, err := ParsePreKeyMessage(enc)
	require.NoError(t, err)
	require.Equal(t, msg.MessageVersion(), dec.MessageVersion())
	require.Equal(t, msg.RegistrationID(), dec.RegistrationID())
	require.NotNil(t, dec.PreKeyID())
	require.Equal(t, *msg.PreKeyID(), *dec.PreKeyID())
	require.Equal(t, msg.SignedPreKeyID(), dec.SignedPreKeyID())
	require.Equal(t, msg.BaseKey(), dec.BaseKey())
	require.Equal(t, msg.IdentityKey().PublicKey, dec.IdentityKey().PublicKey)
	require.Equal(t, PreKeyType, dec.Type())
	require.Equal(t, SignalType, dec.SignalMessage().Type())

	ok, err := dec.VerifyMAC(senderIdentity, receiverIdentity, macKey)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestPreKeyMessageWithoutPreKey(t *testing.T) {
	macKey := bytes.Repeat([]byte{0x33}, 32)
	senderRatchet := mustHex32(t, "1111111111111111111111111111111111111111111111111111111111111111")
	senderIdentity := keys.IdentityKey{PublicKey: mustHex32(t, "2222222222222222222222222222222222222222222222222222222222222222")}
	receiverIdentity := keys.IdentityKey{PublicKey: mustHex32(t, "3333333333333333333333333333333333333333333333333333333333333333")}
	ciphertext := []byte("abc")

	signalMsg, err := NewSignalMessage(3, macKey, senderRatchet, 1, 0, ciphertext, senderIdentity, receiverIdentity, nil)
	require.NoError(t, err)

	baseKey := mustHex32(t, "4444444444444444444444444444444444444444444444444444444444444444")
	identityKey := keys.IdentityKey{PublicKey: mustHex32(t, "5555555555555555555555555555555555555555555555555555555555555555")}

	msg, err := NewPreKeyMessage(3, 1, nil, 2, nil, nil, baseKey, identityKey, signalMsg)
	require.NoError(t, err)

	enc := msg.Serialize()
	dec, err := ParsePreKeyMessage(enc)
	require.NoError(t, err)
	require.Nil(t, dec.PreKeyID())
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
