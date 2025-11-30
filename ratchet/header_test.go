package ratchet

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHeaderSerializeRoundTrip(t *testing.T) {
	h := &Header{
		DH: mustHex32(t, "abababababababababababababababababababababababababababababababab"),
		PN: 5,
		N:  10,
	}
	enc := h.Serialize()
	require.Len(t, enc, 40)

	decoded, err := DeserializeHeader(enc)
	require.NoError(t, err)
	require.Equal(t, h, decoded)
	require.NoError(t, decoded.Validate())
}

func TestDeserializeHeaderInvalidLength(t *testing.T) {
	_, err := DeserializeHeader([]byte{0x01})
	require.Error(t, err)
}

func TestEncryptDecryptHeader(t *testing.T) {
	h := &Header{
		DH: mustHex32(t, "abababababababababababababababababababababababababababababababab"),
		PN: 1,
		N:  2,
	}
	key := make([]byte, 32)
	nonce := make([]byte, 12)

	ct, err := EncryptHeader(h, key, nonce)
	require.NoError(t, err)
	require.NotEmpty(t, ct)

	dec, err := DecryptHeader(key, nonce, ct)
	require.NoError(t, err)
	require.Equal(t, h, dec)
}
