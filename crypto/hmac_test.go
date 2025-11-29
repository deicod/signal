package crypto

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// RFC 4231 test vectors for HMAC-SHA256/512.
func TestHMACVectors(t *testing.T) {
	vectors := []struct {
		name string
		key  string
		data string
		h256 string
		h512 string
	}{
		{
			name: "Case1",
			key:  "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			data: "4869205468657265", // "Hi There"
			h256: "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
			h512: "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde" +
				"daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
		},
		{
			name: "Case2",
			key:  "4a656665",                                                 // "Jefe"
			data: "7768617420646f2079612077616e7420666f72206e6f7468696e673f", // what do ya want for nothing?
			h256: "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
			h512: "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554" +
				"9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
		},
		{
			name: "Case3_LongKey",
			key:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			data: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
			h256: "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
			h512: "fa73b0089d56a284efb0f0756c890be9" +
				"b1b5dbdd8ee81a3655f83e33b2279d39" +
				"bf3e848279a722c806b485a47e67c807" +
				"b946a337bee8942674278859e13292fb",
		},
	}

	for _, tt := range vectors {
		t.Run(tt.name, func(t *testing.T) {
			key := mustHexBytes(t, tt.key)
			data := mustHexBytes(t, tt.data)
			want256 := mustHexBytes(t, tt.h256)
			want512 := mustHexBytes(t, tt.h512)

			got256 := HMAC256(key, data)
			require.Equal(t, want256, got256)

			got512 := HMAC512(key, data)
			require.Equal(t, want512, got512)

			require.True(t, HMACVerify(key, data, want256))
			require.False(t, HMACVerify(key, data, append([]byte{}, want256[:len(want256)-1]...)))
		})
	}
}

func BenchmarkHMAC256(b *testing.B) {
	key := []byte("benchmark-hmac-key")
	data := []byte("benchmark-hmac-data")
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		_ = HMAC256(key, data)
	}
}

func BenchmarkHMAC512(b *testing.B) {
	key := []byte("benchmark-hmac-key")
	data := []byte("benchmark-hmac-data")
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		_ = HMAC512(key, data)
	}
}
