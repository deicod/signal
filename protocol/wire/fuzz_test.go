// Package wire holds fuzz tests for wire message parsing.
package wire

import (
	"bytes"
	"testing"

	"github.com/deicod/signal/keys"
)

func FuzzParseSignalMessageDoesNotPanic(f *testing.F) {
	macKey := bytes.Repeat([]byte{0xab}, 32)
	senderRatchet := mustHex32(f, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	senderIdentity := keys.IdentityKey{PublicKey: mustHex32(f, "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100")}
	receiverIdentity := keys.IdentityKey{PublicKey: mustHex32(f, "ffffffffeeeeeeeeddddddddccccccccbbbbbbbbaaaaaaaa9999999988888888")}
	ciphertext := []byte{0x01, 0x02, 0x03, 0x04}

	msg, err := NewSignalMessage(3, macKey, senderRatchet, 9, 8, ciphertext, senderIdentity, receiverIdentity, nil)
	if err == nil {
		f.Add(msg.Serialize())
	}
	f.Add([]byte{})
	f.Add([]byte{0})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseSignalMessage(data)
	})
}

func FuzzParsePreKeySignalMessageDoesNotPanic(f *testing.F) {
	macKey := bytes.Repeat([]byte{0xcd}, 32)
	senderRatchet := mustHex32(f, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	senderIdentity := keys.IdentityKey{PublicKey: mustHex32(f, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")}
	receiverIdentity := keys.IdentityKey{PublicKey: mustHex32(f, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")}
	ciphertext := []byte("hello")

	signalMsg, err := NewSignalMessage(3, macKey, senderRatchet, 1, 0, ciphertext, senderIdentity, receiverIdentity, nil)
	if err != nil {
		f.Fuzz(func(t *testing.T, data []byte) {
			_, _ = ParsePreKeySignalMessage(data)
		})
		return
	}

	registrationID := uint32(9)
	preKeyID := uint32(23)
	signedPreKeyID := uint32(802)
	baseKey := mustHex32(f, "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
	identityKey := keys.IdentityKey{PublicKey: mustHex32(f, "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")}

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
	if err == nil {
		f.Add(preKeyMsg.Serialize())
	}

	kyberID := uint32(42)
	kyberCT := []byte{0x10, 0x11, 0x12}
	preKeyMsgV4, err := NewPreKeySignalMessage(
		4,
		registrationID,
		&preKeyID,
		signedPreKeyID,
		&kyberID,
		kyberCT,
		baseKey,
		identityKey,
		signalMsg,
	)
	if err == nil {
		f.Add(preKeyMsgV4.Serialize())
	}
	f.Add([]byte{})
	f.Add([]byte{0})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParsePreKeySignalMessage(data)
	})
}
