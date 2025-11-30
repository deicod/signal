package protocol

import (
	"testing"

	"github.com/deicod/signal/keys"
	"github.com/stretchr/testify/require"
)

func TestSignalMessageSerializeRoundTrip(t *testing.T) {
	var rk [32]byte
	for i := range rk {
		rk[i] = byte(i)
	}
	msg := &SignalMessage{
		Version:         1,
		RatchetKey:      rk,
		Counter:         10,
		PreviousCounter: 2,
		Ciphertext:      []byte("cipher"),
	}
	macKey := []byte("mac-key")
	msg.ComputeMAC(macKey)

	enc := msg.Serialize()
	dec, err := DeserializeSignalMessage(enc)
	require.NoError(t, err)
	require.Equal(t, msg.Version, dec.Version)
	require.Equal(t, msg.RatchetKey, dec.RatchetKey)
	require.Equal(t, msg.Counter, dec.Counter)
	require.Equal(t, msg.PreviousCounter, dec.PreviousCounter)
	require.Equal(t, msg.Ciphertext, dec.Ciphertext)
	require.True(t, dec.VerifyMAC(macKey))

	// Tamper MAC
	dec.MAC[0] ^= 0xFF
	require.False(t, dec.VerifyMAC(macKey))
}

func TestPreKeyMessageSerializeRoundTrip(t *testing.T) {
	identity, _ := keys.GenerateIdentityKeyPair()
	var base [32]byte
	copy(base[:], []byte("base-key-012345678901234567890123"))
	signalMsg := &SignalMessage{
		Version:    1,
		RatchetKey: base,
		Counter:    1,
		Ciphertext: []byte("cipher"),
	}
	signalMsg.ComputeMAC([]byte("mac"))
	preKeyID := uint32(7)

	msg := &PreKeyMessage{
		Version:        1,
		RegistrationID: 5,
		PreKeyID:       &preKeyID,
		SignedPreKeyID: 9,
		BaseKey:        base,
		IdentityKey:    identity.PublicKey,
		SignalMessage:  signalMsg,
	}

	enc := msg.Serialize()
	dec, err := DeserializePreKeyMessage(enc)
	require.NoError(t, err)
	require.Equal(t, msg.Version, dec.Version)
	require.Equal(t, msg.RegistrationID, dec.RegistrationID)
	require.NotNil(t, dec.PreKeyID)
	require.Equal(t, *msg.PreKeyID, *dec.PreKeyID)
	require.Equal(t, msg.SignedPreKeyID, dec.SignedPreKeyID)
	require.Equal(t, msg.BaseKey, dec.BaseKey)
	require.Equal(t, msg.IdentityKey.PublicKey, dec.IdentityKey.PublicKey)
	require.True(t, dec.VerifyMAC([]byte("mac")))
	require.Equal(t, PreKeyType, dec.Type())
	require.Equal(t, SignalType, dec.SignalMessage.Type())
}

func TestPreKeyMessageWithoutPreKey(t *testing.T) {
	identity, _ := keys.GenerateIdentityKeyPair()
	sig := &SignalMessage{
		Version:    1,
		Ciphertext: []byte("abc"),
	}
	msg := &PreKeyMessage{
		Version:        1,
		RegistrationID: 1,
		SignedPreKeyID: 2,
		IdentityKey:    identity.PublicKey,
		SignalMessage:  sig,
	}
	enc := msg.Serialize()
	dec, err := DeserializePreKeyMessage(enc)
	require.NoError(t, err)
	require.Nil(t, dec.PreKeyID)
}
