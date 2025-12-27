package crypto

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
)

func TestXEdDSAVector(t *testing.T) {
	priv := mustHex32XEd(t, "c097248412e58bf05df487968205132794178e367637f5818f81e0e6ce73e865")
	pub := mustHex32XEd(t, "ab7e717d4a163b7d9a1d8071dfe9dcf8cdcd1cea3339b6356be84d887e322c64")
	msg := mustHexBytesXEd(t, "05edce9d9c415ca78cb7252e72c2c4a554d3eb29485a0e1d503118d1a82d99fb4a")
	sig := mustHexBytesXEd(t, "5de88ca9a89b4a115da79109c67c9c7464a3e4180274f1cb8c63c2984e286dfbede82deb9dcd9fae0bfbb821569b3d9001bd8130cd11d486cef047bd60b86e88")

	derived, err := curve25519.X25519(priv[:], curve25519.Basepoint[:])
	require.NoError(t, err)
	require.Equal(t, pub[:], derived)

	require.True(t, XEdDSAVerify(pub, sig, msg))
	badSig := append([]byte{}, sig...)
	badSig[0] ^= 0x01
	require.False(t, XEdDSAVerify(pub, badSig, msg))
}

func TestXEdDSASignVerifyRoundTrip(t *testing.T) {
	kp, err := GenerateKeyPair()
	require.NoError(t, err)

	msg := []byte("xeddsa roundtrip")
	sig, err := XEdDSASign(kp.PrivateKey, msg)
	require.NoError(t, err)
	require.True(t, XEdDSAVerify(kp.PublicKey, sig, msg))
}

func mustHex32XEd(tb testing.TB, s string) [32]byte {
	tb.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(tb, err)
	require.Len(tb, b, 32)
	var out [32]byte
	copy(out[:], b)
	return out
}

func mustHexBytesXEd(tb testing.TB, s string) []byte {
	tb.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(tb, err)
	return b
}
