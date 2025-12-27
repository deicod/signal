package crypto

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAESCBCEncryptDecrypt(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	iv := bytes.Repeat([]byte{0x24}, 16)

	plaintext := []byte("hello group cipher")
	ciphertext, err := AESCBCEncrypt(key, iv, plaintext)
	require.NoError(t, err)

	decrypted, err := AESCBCDecrypt(key, iv, ciphertext)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}

func TestAESCBCDecryptRejectsBadPadding(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	iv := bytes.Repeat([]byte{0x24}, 16)

	plaintext := []byte("hello")
	ciphertext, err := AESCBCEncrypt(key, iv, plaintext)
	require.NoError(t, err)

	ciphertext[len(ciphertext)-1] ^= 0xff
	_, err = AESCBCDecrypt(key, iv, ciphertext)
	require.Error(t, err)
}
