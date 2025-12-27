package sealedsender_test

import (
	"testing"
	"time"

	"github.com/deicod/signal"
	"github.com/deicod/signal/sealedsender"
	"github.com/deicod/signal/store/memory"
	"github.com/stretchr/testify/require"
)

func TestSealedSenderV1EncryptDecrypt(t *testing.T) {
	fx := buildCertFixture(t)
	recipient, err := signal.GenerateIdentityKeyPair()
	require.NoError(t, err)

	usmc, err := sealedsender.NewUnidentifiedSenderMessageContent(
		sealedsender.MessageTypeSignal,
		fx.senderCert,
		[]byte("payload"),
		sealedsender.ContentHintDefault,
		nil,
	)
	require.NoError(t, err)

	ciphertext, err := sealedsender.EncryptV1(recipient.PublicKey.PublicKey, fx.senderKey, usmc)
	require.NoError(t, err)

	parsed, err := sealedsender.DecryptToUSMC(ciphertext, recipient)
	require.NoError(t, err)
	require.Equal(t, sealedsender.MessageTypeSignal, parsed.MessageType())
	require.Equal(t, []byte("payload"), parsed.Content())
}

func TestSealedSenderV2EncryptDecrypt(t *testing.T) {
	fx := buildCertFixture(t)
	recipient, err := signal.GenerateIdentityKeyPair()
	require.NoError(t, err)

	usmc, err := sealedsender.NewUnidentifiedSenderMessageContent(
		sealedsender.MessageTypeSignal,
		fx.senderCert,
		[]byte("payload-v2"),
		sealedsender.ContentHintDefault,
		nil,
	)
	require.NoError(t, err)

	ciphertext, err := sealedsender.EncryptV2Received(recipient.PublicKey.PublicKey, fx.senderKey, usmc)
	require.NoError(t, err)

	parsed, err := sealedsender.DecryptToUSMC(ciphertext, recipient)
	require.NoError(t, err)
	require.Equal(t, sealedsender.MessageTypeSignal, parsed.MessageType())
	require.Equal(t, []byte("payload-v2"), parsed.Content())
}

func TestSealedSenderWithSession(t *testing.T) {
	aliceID, err := signal.GenerateIdentityKeyPair()
	require.NoError(t, err)
	bobID, err := signal.GenerateIdentityKeyPair()
	require.NoError(t, err)

	aliceStore := memory.NewStore(aliceID, 1)
	bobStore := memory.NewStore(bobID, 1)

	signed, err := signal.GenerateAndStoreSignedPreKey(bobStore, 1)
	require.NoError(t, err)
	kyber, err := signal.GenerateAndStoreKyberPreKey(bobStore, 2)
	require.NoError(t, err)
	pre, err := signal.GenerateAndStorePreKey(bobStore, 3)
	require.NoError(t, err)

	bundle, err := signal.BuildPreKeyBundle(bobStore, 1, &pre.ID, signed.ID, &kyber.ID)
	require.NoError(t, err)

	aliceCipher := signal.NewCipher(aliceStore, signal.Address{Name: "bob", Device: 1})
	bobCipher := signal.NewCipher(bobStore, signal.Address{Name: "alice", Device: 1})

	initial, err := aliceCipher.EncryptWithPreKeyBundle(bundle, []byte("hello"))
	require.NoError(t, err)
	_, err = bobCipher.Decrypt(initial)
	require.NoError(t, err)

	inner, err := aliceCipher.Encrypt([]byte("sealed-sender"))
	require.NoError(t, err)

	fx := buildCertFixture(t)
	senderCert, err := sealedsender.NewSenderCertificate(sealedsender.SenderCertificateParams{
		SenderUUID:    "alice",
		SenderDevice:  1,
		ExpiresAt:     time.Now().Add(24 * time.Hour),
		IdentityKey:   aliceID.PublicKey.PublicKey,
		Signer:        fx.serverCert,
		SignerPrivate: fx.serverKey.PrivateKey,
	})
	require.NoError(t, err)

	usmc, err := sealedsender.NewUnidentifiedSenderMessageContent(
		sealedsender.MessageTypeSignal,
		senderCert,
		inner,
		sealedsender.ContentHintDefault,
		nil,
	)
	require.NoError(t, err)

	sealedMsg, err := sealedsender.EncryptV1(bobID.PublicKey.PublicKey, aliceID, usmc)
	require.NoError(t, err)

	parsed, err := sealedsender.DecryptToUSMC(sealedMsg, bobID)
	require.NoError(t, err)

	ok, err := parsed.Sender().Validate([][32]byte{fx.trustRoot.PublicKey.PublicKey}, time.Now(), nil)
	require.NoError(t, err)
	require.True(t, ok)

	plaintext, err := bobCipher.Decrypt(parsed.Content())
	require.NoError(t, err)
	require.Equal(t, []byte("sealed-sender"), plaintext)
}
