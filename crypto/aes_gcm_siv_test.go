package crypto

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAESGCMSIVRoundTrip(t *testing.T) {
	key, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	require.NoError(t, err)
	nonce := make([]byte, AESGCMSIVNonceSize)
	plaintext := []byte("sealed sender v2")

	ciphertext, err := AESGCMSIVEncrypt(key, nonce, plaintext, nil)
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext)

	decrypted, err := AESGCMSIVDecrypt(key, nonce, ciphertext, nil)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)

	ciphertext[len(ciphertext)-1] ^= 0x01
	_, err = AESGCMSIVDecrypt(key, nonce, ciphertext, nil)
	require.Error(t, err)
}
