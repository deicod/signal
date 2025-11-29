package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHKDFVectorsRFC5869(t *testing.T) {
	vectors := []struct {
		name   string
		ikm    string
		salt   string
		info   string
		length int
		prk    string
		okm    string
	}{
		{
			name:   "Case1_SHA256_Basic",
			ikm:    "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			salt:   "000102030405060708090a0b0c",
			info:   "f0f1f2f3f4f5f6f7f8f9",
			length: 42,
			prk:    "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
			okm:    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
		},
		{
			name: "Case2_SHA256_LongInputs",
			ikm: "000102030405060708090a0b0c0d0e0f" +
				"101112131415161718191a1b1c1d1e1f" +
				"202122232425262728292a2b2c2d2e2f" +
				"303132333435363738393a3b3c3d3e3f" +
				"404142434445464748494a4b4c4d4e4f",
			salt: "606162636465666768696a6b6c6d6e6f" +
				"707172737475767778797a7b7c7d7e7f" +
				"808182838485868788898a8b8c8d8e8f" +
				"909192939495969798999a9b9c9d9e9f" +
				"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
			info: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
				"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf" +
				"d0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
				"e0e1e2e3e4e5e6e7e8e9eaebecedeeef" +
				"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
			length: 82,
			prk:    "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
			okm: "b11e398dc80327a1c8e7f78c596a4934" +
				"4f012eda2d4efad8a050cc4c19afa97c" +
				"59045a99cac7827271cb41c65e590e09" +
				"da3275600c2f09b8367793a9aca3db71" +
				"cc30c58179ec3e87c14c01d5c1f3434f" +
				"1d87",
		},
		{
			name:   "Case3_SHA256_ZeroSaltInfo",
			ikm:    "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			salt:   "",
			info:   "",
			length: 42,
			prk:    "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
			okm:    "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
		},
	}

	for _, tt := range vectors {
		t.Run(tt.name, func(t *testing.T) {
			ikm := mustHex(t, tt.ikm)
			salt := mustHex(t, tt.salt)
			info := mustHex(t, tt.info)
			wantPRK := mustHex(t, tt.prk)
			wantOKM := mustHex(t, tt.okm)

			prk := HKDFExtract(salt, ikm)
			require.Equal(t, wantPRK, prk)

			okm, err := HKDFExpand(prk, info, tt.length)
			require.NoError(t, err)
			require.Equal(t, wantOKM, okm)

			combined, err := HKDF(ikm, salt, info, tt.length)
			require.NoError(t, err)
			require.Equal(t, wantOKM, combined)
		})
	}
}

func TestHKDFExpandLengthValidation(t *testing.T) {
	prk := HKDFExtract(nil, []byte("secret"))

	_, err := HKDFExpand(prk, nil, hkdfMaxLength+1)
	require.ErrorIs(t, err, ErrHKDFLength)

	_, err = HKDFExpand(prk, nil, -1)
	require.ErrorIs(t, err, ErrHKDFLength)
}

func BenchmarkHKDF(b *testing.B) {
	ikm := make([]byte, 32)
	_, _ = rand.Read(ikm)
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	info := []byte("benchmark-hkdf")

	b.ReportAllocs()
	b.SetBytes(int64(len(ikm)))
	for i := 0; i < b.N; i++ {
		if _, err := HKDF(ikm, salt, info, 32); err != nil {
			b.Fatalf("hkdf failed: %v", err)
		}
	}
}

func mustHex(tb testing.TB, hexStr string) []byte {
	tb.Helper()
	if hexStr == "" {
		return nil
	}
	out, err := hex.DecodeString(hexStr)
	require.NoError(tb, err)
	return out
}
