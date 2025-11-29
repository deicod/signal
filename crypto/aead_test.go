package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAESGCMVector(t *testing.T) {
	// NIST AES-GCM test case: zero key, zero nonce, empty plaintext/aad -> tag 530f8afb...
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	expectedTag := mustHexBytes(t, "530f8afbc74536b9a963b4f1c4cb738b")

	a := NewAESGCM(bytes.NewReader(nonce))
	ct, err := a.Encrypt(key, nil, nil)
	require.NoError(t, err)
	require.Len(t, ct, len(nonce)+len(expectedTag))
	require.Equal(t, nonce, ct[:len(nonce)])
	require.Equal(t, expectedTag, ct[len(nonce):])

	plain, err := a.Decrypt(key, ct, nil)
	require.NoError(t, err)
	require.Empty(t, plain)
}

func TestAESGCMDecryptTamperFails(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	nonce := make([]byte, 12)
	a := NewAESGCM(bytes.NewReader(nonce))

	ct, err := a.Encrypt(key, []byte("secret"), []byte("aad"))
	require.NoError(t, err)

	ct[len(ct)-1] ^= 0x01
	_, err = a.Decrypt(key, ct, []byte("aad"))
	require.Error(t, err)
}

func TestChaCha20Poly1305Vector(t *testing.T) {
	key := mustHexBytes(t, "a5117e70953568bf750862df9e6f92af81677c3a188e847917a4a915bda7792e")
	nonce := mustHexBytes(t, "129039b5572e8a7a8131f76a")
	aad := mustHexBytes(t, "00000000000000001603030010")
	plaintext := mustHexBytes(t, "1400000cebccee3bf561b292340fec60")
	expectedCipher := mustHexBytes(t, "2b487a2941bc07f3cc76d1a531662588ee7c2598e59778c24d5b27559a80d163")

	c := NewChaChaAEAD(bytes.NewReader(nonce))
	ct, err := c.Encrypt(key, plaintext, aad)
	require.NoError(t, err)
	require.Equal(t, append(nonce, expectedCipher...), ct)

	plain, err := c.Decrypt(key, ct, aad)
	require.NoError(t, err)
	require.Equal(t, plaintext, plain)
}

func TestAEADInvalidKey(t *testing.T) {
	a := NewAESGCM(nil)
	_, err := a.Encrypt([]byte("short"), nil, nil)
	require.ErrorIs(t, err, ErrInvalidKey)

	c := NewChaChaAEAD(nil)
	_, err = c.Encrypt([]byte("short"), nil, nil)
	require.ErrorIs(t, err, ErrInvalidKey)
}

func mustHexBytes(tb testing.TB, s string) []byte {
	tb.Helper()
	if s == "" {
		return nil
	}
	out, err := hex.DecodeString(s)
	require.NoError(tb, err)
	return out
}
