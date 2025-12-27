package signal_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deicod/signal"
	signalcrypto "github.com/deicod/signal/crypto"
	"github.com/deicod/signal/keys"
	wire "github.com/deicod/signal/protocol/wire"
	"github.com/deicod/signal/store/memory"
	"github.com/stretchr/testify/require"
)

type libsignalSessionFixture struct {
	Name                    string                `json:"name"`
	RegistrationIDAlice     uint32                `json:"registration_id_alice"`
	RegistrationIDBob       uint32                `json:"registration_id_bob"`
	DeviceIDBob             uint32                `json:"device_id_bob"`
	Alice                   libsignalIdentity     `json:"alice"`
	Bob                     libsignalBobKeys      `json:"bob"`
	BobSenderRatchetPrivate string                `json:"bob_sender_ratchet_private"`
	Messages                []libsignalMessageVec `json:"messages"`
}

type libsignalIdentity struct {
	IdentityPrivate string `json:"identity_private"`
}

type libsignalBobKeys struct {
	IdentityPrivate       string `json:"identity_private"`
	SignedPreKeyID        uint32 `json:"signed_pre_key_id"`
	SignedPreKeyPrivate   string `json:"signed_pre_key_private"`
	SignedPreKeySignature string `json:"signed_pre_key_signature"`
	PreKeyID              uint32 `json:"pre_key_id"`
	PreKeyPrivate         string `json:"pre_key_private"`
	KyberPreKeyID         uint32 `json:"kyber_pre_key_id"`
	KyberPublic           string `json:"kyber_public"`
	KyberPrivate          string `json:"kyber_private"`
	KyberSignature        string `json:"kyber_signature"`
}

type libsignalMessageVec struct {
	Kind       string `json:"kind"`
	Ciphertext string `json:"ciphertext"`
	Plaintext  string `json:"plaintext"`
}

func TestLibsignalSessionVectorsParse(t *testing.T) {
	fixture := loadLibsignalSessionFixture(t)

	for _, message := range fixture.Messages {
		ciphertext := mustHexBytes(t, message.Ciphertext)
		var pqLen int
		switch message.Kind {
		case "prekey":
			preKey, err := wire.ParsePreKeySignalMessage(ciphertext)
			require.NoError(t, err)
			pqLen = len(preKey.Message().PQRatchet())
		case "signal":
			signalMsg, err := wire.ParseSignalMessage(ciphertext)
			require.NoError(t, err)
			pqLen = len(signalMsg.PQRatchet())
		default:
			t.Fatalf("unknown message kind %q", message.Kind)
		}
		require.NotZero(t, pqLen)
	}
}

func TestLibsignalSessionVectorsDecrypt(t *testing.T) {
	fixture := loadLibsignalSessionFixture(t)

	bobIdentity := identityKeyPairFromHex(t, fixture.Bob.IdentityPrivate)
	bobStore := memory.NewStore(bobIdentity, fixture.RegistrationIDBob)
	bobStore.SetSignedPreKeyMaxAge(0)

	preKey := preKeyFromHex(t, fixture.Bob.PreKeyID, fixture.Bob.PreKeyPrivate)
	require.NoError(t, bobStore.StorePreKey(preKey.ID, preKey))
	signedPreKey := signedPreKeyFromHex(
		t,
		fixture.Bob.SignedPreKeyID,
		fixture.Bob.SignedPreKeyPrivate,
		fixture.Bob.SignedPreKeySignature,
	)
	require.NoError(t, bobStore.StoreSignedPreKey(signedPreKey.ID, signedPreKey))
	kyberPreKey := kyberPreKeyFromHex(
		t,
		fixture.Bob.KyberPreKeyID,
		fixture.Bob.KyberPublic,
		fixture.Bob.KyberPrivate,
		fixture.Bob.KyberSignature,
	)
	require.NoError(t, bobStore.StoreKyberPreKey(kyberPreKey.ID, kyberPreKey))

	bobCipher := signal.NewCipher(bobStore, signal.Address{Name: "alice", Device: 1})

	for _, message := range fixture.Messages {
		ciphertext := mustHexBytes(t, message.Ciphertext)
		var restore func()
		if message.Kind == "prekey" {
			require.NotEmpty(t, fixture.BobSenderRatchetPrivate)
			priv := mustHex32Bytes(t, fixture.BobSenderRatchetPrivate)
			restore = signalcrypto.SetRandReader(bytes.NewReader(priv[:]))
		}
		plaintext, err := bobCipher.Decrypt(ciphertext)
		if restore != nil {
			restore()
		}
		require.NoError(t, err)
		require.Equal(t, mustHexBytes(t, message.Plaintext), plaintext)
	}
}

func loadLibsignalSessionFixture(t *testing.T) libsignalSessionFixture {
	t.Helper()
	path := filepath.Join("testing", "vectors", "session_libsignal.json")
	raw := mustReadFile(t, path)

	var fixture libsignalSessionFixture
	require.NoError(t, json.Unmarshal(raw, &fixture))
	return fixture
}

func identityKeyPairFromHex(t *testing.T, privateHex string) *keys.IdentityKeyPair {
	t.Helper()
	private := mustHex32Bytes(t, privateHex)
	kp, err := signalcrypto.KeyPairFromPrivate(private)
	require.NoError(t, err)
	signingPublic, err := signalcrypto.XEdDSASigningPublicKey(private)
	require.NoError(t, err)
	return &keys.IdentityKeyPair{
		PublicKey: keys.IdentityKey{
			PublicKey:     kp.PublicKey,
			SigningPublic: signingPublic,
		},
		PrivateKey: private,
	}
}

func preKeyFromHex(t *testing.T, id uint32, privateHex string) *keys.PreKey {
	t.Helper()
	private := mustHex32Bytes(t, privateHex)
	kp, err := signalcrypto.KeyPairFromPrivate(private)
	require.NoError(t, err)
	return &keys.PreKey{
		ID:        id,
		KeyPair:   kp,
		Timestamp: time.Now().UTC(),
	}
}

func signedPreKeyFromHex(t *testing.T, id uint32, privateHex, signatureHex string) *keys.SignedPreKey {
	t.Helper()
	private := mustHex32Bytes(t, privateHex)
	kp, err := signalcrypto.KeyPairFromPrivate(private)
	require.NoError(t, err)
	return &keys.SignedPreKey{
		ID:        id,
		KeyPair:   kp,
		Signature: mustHexBytes(t, signatureHex),
		Timestamp: time.Now().UTC(),
	}
}

func kyberPreKeyFromHex(t *testing.T, id uint32, publicHex, privateHex, signatureHex string) *keys.KyberPreKey {
	t.Helper()
	return &keys.KyberPreKey{
		ID: id,
		KeyPair: &keys.KyberKeyPair{
			PublicKey:  mustHexBytes(t, publicHex),
			PrivateKey: mustHexBytes(t, privateHex),
		},
		Signature: mustHexBytes(t, signatureHex),
		Timestamp: time.Now().UTC(),
	}
}

func mustHexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func mustHex32Bytes(t *testing.T, s string) [32]byte {
	t.Helper()
	b := mustHexBytes(t, s)
	require.Len(t, b, 32)
	var out [32]byte
	copy(out[:], b)
	return out
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	return raw
}
