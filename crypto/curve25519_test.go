package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateKeyPairAndDH(t *testing.T) {
	k1, err := GenerateKeyPair()
	require.NoError(t, err)
	require.NotNil(t, k1)

	k2, err := GenerateKeyPair()
	require.NoError(t, err)

	shared12, err := DH(k1.PrivateKey, k2.PublicKey)
	require.NoError(t, err)

	shared21, err := DH(k2.PrivateKey, k1.PublicKey)
	require.NoError(t, err)

	var zero [32]byte
	require.NotEqual(t, zero, shared12)
	require.Equal(t, shared12, shared21)
}

func TestDHWithRFC7748Vectors(t *testing.T) {
	alicePriv := mustHex32(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	alicePubExpected := mustHex32(t, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")

	bobPriv := mustHex32(t, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
	bobPubExpected := mustHex32(t, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")

	sharedExpected := mustHex32(t, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

	alicePub, err := scalarBaseMult(alicePriv)
	require.NoError(t, err)
	require.Equal(t, alicePubExpected, alicePub)

	bobPub, err := scalarBaseMult(bobPriv)
	require.NoError(t, err)
	require.Equal(t, bobPubExpected, bobPub)

	sharedAB, err := DH(alicePriv, bobPub)
	require.NoError(t, err)
	require.Equal(t, sharedExpected, sharedAB)

	sharedBA, err := DH(bobPriv, alicePub)
	require.NoError(t, err)
	require.Equal(t, sharedExpected, sharedBA)
	require.Equal(t, sharedAB, sharedBA)
}

func TestDHRejectsLowOrderPublicKey(t *testing.T) {
	var priv [32]byte
	_, err := rand.Read(priv[:])
	require.NoError(t, err)

	var lowOrderPublic [32]byte
	_, err = DH(priv, lowOrderPublic)
	require.ErrorIs(t, err, ErrInvalidPublicKey)
}

func BenchmarkDH(b *testing.B) {
	priv, err := GenerateKeyPair()
	require.NoError(b, err)

	peer, err := GenerateKeyPair()
	require.NoError(b, err)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := DH(priv.PrivateKey, peer.PublicKey)
		if err != nil {
			b.Fatalf("dh failed: %v", err)
		}
	}
}

func mustHex32(tb testing.TB, hexStr string) [32]byte {
	tb.Helper()
	raw, err := hex.DecodeString(hexStr)
	require.NoError(tb, err)
	if len(raw) != 32 {
		tb.Fatalf("expected 32 bytes, got %d", len(raw))
	}
	var out [32]byte
	copy(out[:], raw)
	return out
}
