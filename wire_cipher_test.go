package signal_test

import (
	"testing"

	"github.com/deicod/signal"
	wire "github.com/deicod/signal/protocol/wire"
	"github.com/deicod/signal/store/memory"
	"github.com/stretchr/testify/require"
)

func TestCipherUsesWireFormats(t *testing.T) {
	aliceID, err := signal.GenerateIdentityKeyPair()
	require.NoError(t, err)
	bobID, err := signal.GenerateIdentityKeyPair()
	require.NoError(t, err)

	aliceStore := memory.NewStore(aliceID, 1)
	bobStore := memory.NewStore(bobID, 2)

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

	preKeyMsg, err := wire.ParsePreKeySignalMessage(initial)
	require.NoError(t, err)
	require.Equal(t, uint8(4), preKeyMsg.MessageVersion())
	require.NotNil(t, preKeyMsg.PreKeyID())
	require.Equal(t, pre.ID, *preKeyMsg.PreKeyID())
	require.Equal(t, signed.ID, preKeyMsg.SignedPreKeyID())
	require.NotNil(t, preKeyMsg.KyberPreKeyID())
	require.Equal(t, kyber.ID, *preKeyMsg.KyberPreKeyID())
	require.NotEmpty(t, preKeyMsg.KyberCiphertext())
	regID, err := aliceStore.GetLocalRegistrationID()
	require.NoError(t, err)
	require.Equal(t, regID, preKeyMsg.RegistrationID())

	pt, err := bobCipher.Decrypt(initial)
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), pt)

	reply, err := bobCipher.Encrypt([]byte("pong"))
	require.NoError(t, err)

	signalMsg, err := wire.ParseSignalMessage(reply)
	require.NoError(t, err)
	require.Equal(t, uint8(4), signalMsg.MessageVersion())
	require.NotEmpty(t, signalMsg.Ciphertext())

	back, err := aliceCipher.Decrypt(reply)
	require.NoError(t, err)
	require.Equal(t, []byte("pong"), back)
}
