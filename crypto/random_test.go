package crypto

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRandomBytesLengthAndUniqueness(t *testing.T) {
	out, err := RandomBytes(32)
	require.NoError(t, err)
	require.Len(t, out, 32)

	out2, err := RandomBytes(32)
	require.NoError(t, err)
	require.Len(t, out2, 32)
	require.NotEqual(t, out, out2, "random outputs should differ")
}

func TestRandomBytesInvalidLength(t *testing.T) {
	_, err := RandomBytes(-1)
	require.ErrorIs(t, err, ErrInvalidLength)
}

func TestRandomBytesEntropyError(t *testing.T) {
	orig := randReader
	t.Cleanup(func() { randReader = orig })

	randReader = &errReader{}
	_, err := RandomBytes(8)
	require.Error(t, err)
	require.True(t, errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF))
}

func TestRandomScalarClampsBits(t *testing.T) {
	orig := randReader
	t.Cleanup(func() { randReader = orig })

	seed := bytes.Repeat([]byte{0xFF}, 32)
	randReader = bytes.NewReader(seed)

	scalar, err := RandomScalar()
	require.NoError(t, err)
	// Check clamping bits.
	require.Equal(t, byte(0xF8), scalar[0])
	require.Equal(t, byte(0x7F), scalar[31]&0x7F)
	require.Equal(t, byte(0x40), scalar[31]&0x40)
	// Ensure different from input to validate clamping.
	require.NotEqual(t, seed, scalar[:])
}

func TestRandomScalarError(t *testing.T) {
	orig := randReader
	t.Cleanup(func() { randReader = orig })

	randReader = &errReader{}
	_, err := RandomScalar()
	require.Error(t, err)
}

type errReader struct{}

func (e *errReader) Read(_ []byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}
