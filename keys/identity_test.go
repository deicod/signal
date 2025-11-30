package keys

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateIdentityKeyPairAndSignVerify(t *testing.T) {
	pair, err := GenerateIdentityKeyPair()
	require.NoError(t, err)
	require.Len(t, pair.PrivateKey, 32)

	msg := []byte("identity signing test")
	sig, err := pair.Sign(msg)
	require.NoError(t, err)
	require.True(t, pair.PublicKey.Verify(msg, sig))

	// Tamper with message
	badSig := append([]byte{}, sig...)
	badSig[len(badSig)-1] ^= 0x01
	require.False(t, pair.PublicKey.Verify(msg, badSig))
}

func TestFingerprintDeterministic(t *testing.T) {
	curvePub := mustHex32(t, "0102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff00")
	signingPub := mustHex32(t, "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebe")
	key, err := FromBytes(curvePub[:], signingPub[:])
	require.NoError(t, err)

	fp := key.Fingerprint()
	require.Equal(t, "JapxjjWBXljMvlXBlbB2vXdYixW62IVzhEJUff0zoBs", fp)
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
