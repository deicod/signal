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
