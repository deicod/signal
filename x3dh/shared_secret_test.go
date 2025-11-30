package x3dh

import (
	"encoding/hex"
	"testing"

	"github.com/deicod/signal/keys"
	"github.com/stretchr/testify/require"
)

func TestAssociatedDataDeterministic(t *testing.T) {
	init := fixedIdentity(t, "0102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff00", "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebe")
	resp := fixedIdentity(t, "ffffffffeeeeeeeeddddddddccccccccbbbbbbbbaaaaaaaa9999999988888888", "1111111122222222333333334444444455555555666666667777777788888888")
	ad := AssociatedData(init, resp)
	require.Equal(t, "1b6000dfddfae87774ec1470af27c7914aa6b6164c23ea980287ecd067253a07", hex.EncodeToString(ad))
}

func fixedIdentity(tb testing.TB, curveHex, signHex string) keys.IdentityKey {
	tb.Helper()
	return keys.IdentityKey{
		PublicKey:     mustHex32(tb, curveHex),
		SigningPublic: mustHex32(tb, signHex),
	}
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
