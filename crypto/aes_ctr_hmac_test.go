package crypto

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAESCTRHMACSHA256RoundTrip(t *testing.T) {
	key, err := hex.DecodeString("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4")
	require.NoError(t, err)
	macKey, err := hex.DecodeString("9D5C7F6A3D8E2F2C6B94E6A30B2E8D01A5D21E2A8A10D2D8C5B5A4E0D1C8F1E3")
	require.NoError(t, err)

	plaintext := make([]byte, 35)
	ciphertext, err := AES256CTRHMACSHA256Encrypt(plaintext, key, macKey)
	require.NoError(t, err)
	require.Len(t, ciphertext, len(plaintext)+aesCTRHMACSize)

	// Validate AES-CTR output against the libsignal test vector.
	expected := "e568f68194cf76d6174d4cc04310a85491151e5d0b7a1f1bc0d7acd0ae3e51e4170e23"
	require.Equal(t, expected, hex.EncodeToString(ciphertext[:len(plaintext)]))

	decrypted, err := AES256CTRHMACSHA256Decrypt(ciphertext, key, macKey)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)

	ciphertext[len(ciphertext)-1] ^= 0x01
	_, err = AES256CTRHMACSHA256Decrypt(ciphertext, key, macKey)
	require.Error(t, err)
}
