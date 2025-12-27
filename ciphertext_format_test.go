package signal_test

import (
	"testing"

	"github.com/deicod/signal"
	"github.com/deicod/signal/store/memory"
	"github.com/stretchr/testify/require"
)

func TestDetectCiphertextFormat(t *testing.T) {
	aliceID, err := signal.GenerateIdentityKeyPair()
	require.NoError(t, err)
	bobID, err := signal.GenerateIdentityKeyPair()
	require.NoError(t, err)

	bobStore := memory.NewStore(bobID, 2)
	signed, err := signal.GenerateAndStoreSignedPreKey(bobStore, 1)
	require.NoError(t, err)
	kyber, err := signal.GenerateAndStoreKyberPreKey(bobStore, 2)
	require.NoError(t, err)
	bundle, err := signal.BuildPreKeyBundle(bobStore, 1, nil, signed.ID, &kyber.ID)
	require.NoError(t, err)

	wireStore := memory.NewStore(aliceID, 1)
	envelopeStore := memory.NewStore(aliceID, 1)

	wireCipher := signal.NewCipher(wireStore, signal.Address{Name: "bob", Device: 1})
	envelopeCipher := signal.NewEnvelopeCipher(envelopeStore, signal.Address{Name: "bob", Device: 1})

	wireMsg, err := wireCipher.EncryptWithPreKeyBundle(bundle, []byte("hello"))
	require.NoError(t, err)
	legacyMsg, err := envelopeCipher.EncryptWithPreKeyBundle(bundle, []byte("hello"))
	require.NoError(t, err)

	require.Equal(t, signal.CiphertextWire, signal.DetectCiphertextFormat(wireMsg))
	require.Equal(t, signal.CiphertextEnvelope, signal.DetectCiphertextFormat(legacyMsg))
	require.Equal(t, signal.CiphertextUnknown, signal.DetectCiphertextFormat([]byte("nope")))
}
