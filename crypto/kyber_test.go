package crypto

import (
	"testing"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/stretchr/testify/require"
)

func TestKyber1024EncapsulateDecapsulate(t *testing.T) {
	kp, err := GenerateKyber1024KeyPair()
	require.NoError(t, err)
	require.Len(t, kp.PublicKey, 1+kyber1024.PublicKeySize)
	require.Len(t, kp.PrivateKey, 1+kyber1024.PrivateKeySize)

	ss1, ct, err := Kyber1024Encapsulate(kp.PublicKey)
	require.NoError(t, err)
	require.Len(t, ct, 1+kyber1024.CiphertextSize)
	require.Len(t, ss1, kyber1024.SharedKeySize)

	ss2, err := Kyber1024Decapsulate(kp.PrivateKey, ct)
	require.NoError(t, err)
	require.Equal(t, ss1, ss2)
}
