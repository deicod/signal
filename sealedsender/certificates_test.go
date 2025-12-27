package sealedsender_test

import (
	"testing"
	"time"

	"github.com/deicod/signal/keys"
	"github.com/deicod/signal/sealedsender"
	"github.com/stretchr/testify/require"
)

type certFixture struct {
	trustRoot  *keys.IdentityKeyPair
	serverKey  *keys.IdentityKeyPair
	serverCert *sealedsender.ServerCertificate
	senderKey  *keys.IdentityKeyPair
	senderCert *sealedsender.SenderCertificate
}

func buildCertFixture(t *testing.T) certFixture {
	t.Helper()

	trustRoot, err := keys.GenerateIdentityKeyPair()
	require.NoError(t, err)
	serverKey, err := keys.GenerateIdentityKeyPair()
	require.NoError(t, err)
	senderKey, err := keys.GenerateIdentityKeyPair()
	require.NoError(t, err)

	serverCert, err := sealedsender.NewServerCertificate(7, serverKey.PublicKey.PublicKey, trustRoot.PrivateKey)
	require.NoError(t, err)

	senderCert, err := sealedsender.NewSenderCertificate(sealedsender.SenderCertificateParams{
		SenderUUID:    "alice",
		SenderE164:    "+15551234567",
		SenderDevice:  1,
		ExpiresAt:     time.Now().Add(24 * time.Hour),
		IdentityKey:   senderKey.PublicKey.PublicKey,
		Signer:        serverCert,
		SignerPrivate: serverKey.PrivateKey,
	})
	require.NoError(t, err)

	return certFixture{
		trustRoot:  trustRoot,
		serverKey:  serverKey,
		serverCert: serverCert,
		senderKey:  senderKey,
		senderCert: senderCert,
	}
}

func TestServerCertificateRoundTrip(t *testing.T) {
	fx := buildCertFixture(t)

	parsed, err := sealedsender.ParseServerCertificate(fx.serverCert.Serialize())
	require.NoError(t, err)
	require.Equal(t, fx.serverCert.KeyID(), parsed.KeyID())
	require.Equal(t, fx.serverCert.PublicKey(), parsed.PublicKey())
	require.True(t, parsed.Validate(fx.trustRoot.PublicKey.PublicKey))

	other, err := keys.GenerateIdentityKeyPair()
	require.NoError(t, err)
	require.False(t, parsed.Validate(other.PublicKey.PublicKey))
}

func TestSenderCertificateRoundTrip(t *testing.T) {
	fx := buildCertFixture(t)

	parsed, err := sealedsender.ParseSenderCertificate(fx.senderCert.Serialize())
	require.NoError(t, err)
	require.Equal(t, fx.senderCert.SenderUUID(), parsed.SenderUUID())
	require.Equal(t, fx.senderCert.SenderDevice(), parsed.SenderDevice())
	require.Equal(t, fx.senderCert.IdentityKey(), parsed.IdentityKey())
	value, ok := parsed.SenderE164()
	require.True(t, ok)
	require.Equal(t, "+15551234567", value)

	ok, err = parsed.Validate([][32]byte{fx.trustRoot.PublicKey.PublicKey}, time.Now(), nil)
	require.NoError(t, err)
	require.True(t, ok)
}
