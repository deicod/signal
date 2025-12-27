package x3dh

import (
	"encoding/binary"
	"testing"

	signalcrypto "github.com/deicod/signal/crypto"
	"github.com/deicod/signal/keys"
	"github.com/stretchr/testify/require"
)

func TestSerializeRoundTripV2(t *testing.T) {
	identity, err := keys.GenerateIdentityKeyPair()
	require.NoError(t, err)
	ephemeral, err := signalcrypto.GenerateKeyPair()
	require.NoError(t, err)

	preID := uint32(7)
	signedID := uint32(9)
	kyberID := uint32(11)
	kyberCT := []byte("kyber-ct")
	ct := []byte("ciphertext")

	msg := &Message{
		IdentityKey:     identity.PublicKey,
		EphemeralKey:    ephemeral.PublicKey,
		PreKeyID:        &preID,
		SignedPreKeyID:  signedID,
		KyberPreKeyID:   &kyberID,
		KyberCiphertext: kyberCT,
		Ciphertext:      ct,
	}

	serialized, err := msg.Serialize()
	require.NoError(t, err)
	require.Equal(t, messageSerializeVersion, serialized[0])

	decoded, err := DeserializeMessage(serialized)
	require.NoError(t, err)
	require.Equal(t, msg.IdentityKey, decoded.IdentityKey)
	require.Equal(t, msg.EphemeralKey, decoded.EphemeralKey)
	require.NotNil(t, decoded.PreKeyID)
	require.Equal(t, preID, *decoded.PreKeyID)
	require.Equal(t, signedID, decoded.SignedPreKeyID)
	require.NotNil(t, decoded.KyberPreKeyID)
	require.Equal(t, kyberID, *decoded.KyberPreKeyID)
	require.Equal(t, kyberCT, decoded.KyberCiphertext)
	require.Equal(t, ct, decoded.Ciphertext)
}

func TestDeserializeMessageV1(t *testing.T) {
	identity, err := keys.GenerateIdentityKeyPair()
	require.NoError(t, err)
	ephemeral, err := signalcrypto.GenerateKeyPair()
	require.NoError(t, err)

	signedID := uint32(19)
	ciphertext := []byte("legacy-ct")
	preID := uint32(17)

	tests := []struct {
		name     string
		preKeyID *uint32
	}{
		{name: "WithPreKey", preKeyID: &preID},
		{name: "WithoutPreKey", preKeyID: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := buildV1Message(identity.PublicKey, ephemeral.PublicKey, tt.preKeyID, signedID, ciphertext)
			decoded, err := DeserializeMessage(data)
			require.NoError(t, err)
			require.Equal(t, identity.PublicKey, decoded.IdentityKey)
			require.Equal(t, ephemeral.PublicKey, decoded.EphemeralKey)
			if tt.preKeyID == nil {
				require.Nil(t, decoded.PreKeyID)
			} else {
				require.NotNil(t, decoded.PreKeyID)
				require.Equal(t, *tt.preKeyID, *decoded.PreKeyID)
			}
			require.Equal(t, signedID, decoded.SignedPreKeyID)
			require.Nil(t, decoded.KyberPreKeyID)
			require.Nil(t, decoded.KyberCiphertext)
			require.Equal(t, ciphertext, decoded.Ciphertext)
		})
	}
}

func buildV1Message(identity keys.IdentityKey, eph [32]byte, preKeyID *uint32, signedPreKeyID uint32, ciphertext []byte) []byte {
	identityBytes, _ := identity.Serialize()

	out := make([]byte, 1+2+len(identityBytes)+32+1+4+4+4+len(ciphertext))
	pos := 0
	out[pos] = 1
	pos++

	binary.BigEndian.PutUint16(out[pos:pos+2], uint16(len(identityBytes)))
	pos += 2
	copy(out[pos:pos+len(identityBytes)], identityBytes)
	pos += len(identityBytes)

	copy(out[pos:pos+32], eph[:])
	pos += 32

	if preKeyID != nil {
		out[pos] = 1
	}
	pos++

	if preKeyID != nil {
		binary.BigEndian.PutUint32(out[pos:pos+4], *preKeyID)
	}
	pos += 4

	binary.BigEndian.PutUint32(out[pos:pos+4], signedPreKeyID)
	pos += 4

	binary.BigEndian.PutUint32(out[pos:pos+4], uint32(len(ciphertext)))
	pos += 4

	copy(out[pos:], ciphertext)
	return out
}
