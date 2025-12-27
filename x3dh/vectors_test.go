package x3dh

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	signalcrypto "github.com/deicod/signal/crypto"
	"github.com/deicod/signal/keys"
	"github.com/deicod/signal/store/memory"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
)

type x3dhVectorFile struct {
	Cases []x3dhVectorCase `json:"cases"`
}

type x3dhVectorCase struct {
	Name           string             `json:"name"`
	RegistrationID uint32             `json:"registration_id"`
	DeviceID       uint32             `json:"device_id"`
	Initiator      x3dhInitiatorInput `json:"initiator"`
	Responder      x3dhResponderInput `json:"responder"`
	Expected       x3dhExpectedOutput `json:"expected"`
}

type x3dhInitiatorInput struct {
	IdentityPrivate  string `json:"identity_private"`
	EphemeralPrivate string `json:"ephemeral_private"`
}

type x3dhResponderInput struct {
	IdentityPrivate       string  `json:"identity_private"`
	SignedPreKeyID        uint32  `json:"signed_pre_key_id"`
	SignedPreKeyPrivate   string  `json:"signed_pre_key_private"`
	SignedPreKeySignature string  `json:"signed_pre_key_signature"`
	PreKeyID              *uint32 `json:"pre_key_id"`
	PreKeyPrivate         string  `json:"pre_key_private"`
	KyberPreKeyID         *uint32 `json:"kyber_pre_key_id"`
	KyberPublic           string  `json:"kyber_public"`
	KyberPrivate          string  `json:"kyber_private"`
	KyberSignature        string  `json:"kyber_signature"`
}

type x3dhExpectedOutput struct {
	SharedSecret      string `json:"shared_secret"`
	InitialChainKey   string `json:"initial_chain_key"`
	AssociatedData    string `json:"associated_data"`
	KyberCiphertext   string `json:"kyber_ciphertext"`
	MessageSerialized string `json:"message_serialized"`
}

func TestX3DHVectors(t *testing.T) {
	vec := loadX3DHVectors(t)

	for _, tc := range vec.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			initID := identityFromPrivateHex(t, tc.Initiator.IdentityPrivate)
			respID := identityFromPrivateHex(t, tc.Responder.IdentityPrivate)
			initEph := keyPairFromPrivateHex(t, tc.Initiator.EphemeralPrivate)

			signedKP := keyPairFromPrivateHex(t, tc.Responder.SignedPreKeyPrivate)
			signedSig := mustHexBytes(t, tc.Responder.SignedPreKeySignature)
			signedPreKey := &keys.SignedPreKey{
				ID:        tc.Responder.SignedPreKeyID,
				KeyPair:   signedKP,
				Signature: signedSig,
			}

			var preKey *keys.PreKey
			if tc.Responder.PreKeyID != nil {
				preKP := keyPairFromPrivateHex(t, tc.Responder.PreKeyPrivate)
				preKey = &keys.PreKey{ID: *tc.Responder.PreKeyID, KeyPair: preKP}
			}

			var kyberPreKey *keys.KyberPreKey
			if tc.Responder.KyberPreKeyID != nil {
				kyberPreKey = &keys.KyberPreKey{
					ID: *tc.Responder.KyberPreKeyID,
					KeyPair: &keys.KyberKeyPair{
						PublicKey:  mustHexBytes(t, tc.Responder.KyberPublic),
						PrivateKey: mustHexBytes(t, tc.Responder.KyberPrivate),
					},
					Signature: mustHexBytes(t, tc.Responder.KyberSignature),
				}
			}

			bundle, err := keys.NewPreKeyBundleWithKyber(tc.RegistrationID, tc.DeviceID, preKey, signedPreKey, kyberPreKey, respID.PublicKey)
			require.NoError(t, err)

			var encapsulate func(publicKey []byte) ([]byte, []byte, error)
			if tc.Responder.KyberPreKeyID != nil {
				seed := sha256.Sum256([]byte("kyber-encapsulate-" + tc.Name))
				encapsulate = func(publicKey []byte) ([]byte, []byte, error) {
					return signalcrypto.Kyber1024EncapsulateDeterministically(publicKey, seed[:])
				}
			}

			initiator := NewInitiatorWithGenerators(initID, func() (*signalcrypto.KeyPair, error) {
				return initEph, nil
			}, encapsulate)
			initRes, err := initiator.ProcessPreKeyBundle(bundle)
			require.NoError(t, err)

			require.Equal(t, mustHex32Vec(t, tc.Expected.SharedSecret), initRes.SharedSecret)
			require.Equal(t, mustHexBytes(t, tc.Expected.AssociatedData), initRes.AssociatedData)
			if tc.Expected.InitialChainKey == "" {
				require.Nil(t, initRes.InitialChainKey)
			} else {
				require.NotNil(t, initRes.InitialChainKey)
				require.Equal(t, mustHex32Vec(t, tc.Expected.InitialChainKey), *initRes.InitialChainKey)
			}
			if tc.Expected.KyberCiphertext == "" {
				require.Empty(t, initRes.InitialMessage.KyberCiphertext)
			} else {
				require.Equal(t, mustHexBytes(t, tc.Expected.KyberCiphertext), initRes.InitialMessage.KyberCiphertext)
			}

			serialized, err := initRes.InitialMessage.Serialize()
			require.NoError(t, err)
			require.Equal(t, mustHexBytes(t, tc.Expected.MessageSerialized), serialized)

			store := memory.NewStore(respID, tc.RegistrationID)
			if preKey != nil {
				require.NoError(t, store.StorePreKey(preKey.ID, preKey))
			}
			if kyberPreKey != nil {
				require.NoError(t, store.StoreKyberPreKey(kyberPreKey.ID, kyberPreKey))
			}

			responder := NewResponder(respID, signedPreKey, store, store)
			respRes, err := responder.ProcessInitialMessage(&initRes.InitialMessage)
			require.NoError(t, err)
			require.Equal(t, initRes.SharedSecret, respRes.SharedSecret)
			require.Equal(t, initRes.AssociatedData, respRes.AssociatedData)
		})
	}
}

func loadX3DHVectors(t *testing.T) x3dhVectorFile {
	t.Helper()
	path := filepath.Join("..", "testing", "vectors", "x3dh.json")
	raw, err := os.ReadFile(path)
	require.NoError(t, err)

	var vec x3dhVectorFile
	require.NoError(t, json.Unmarshal(raw, &vec))
	return vec
}

func keyPairFromPrivateHex(t *testing.T, hexStr string) *signalcrypto.KeyPair {
	t.Helper()
	var priv [32]byte
	raw := mustHexBytes(t, hexStr)
	require.Len(t, raw, 32)
	copy(priv[:], raw)

	pubBytes, err := curve25519.X25519(priv[:], curve25519.Basepoint[:])
	require.NoError(t, err)
	var pub [32]byte
	copy(pub[:], pubBytes)

	require.NoError(t, signalcrypto.ValidatePublicKey(pub))
	return &signalcrypto.KeyPair{PublicKey: pub, PrivateKey: priv}
}

func identityFromPrivateHex(t *testing.T, hexStr string) *keys.IdentityKeyPair {
	t.Helper()
	kp := keyPairFromPrivateHex(t, hexStr)
	signingPub, err := signalcrypto.XEdDSASigningPublicKey(kp.PrivateKey)
	require.NoError(t, err)
	return &keys.IdentityKeyPair{
		PublicKey: keys.IdentityKey{
			PublicKey:     kp.PublicKey,
			SigningPublic: signingPub,
		},
		PrivateKey: kp.PrivateKey,
	}
}

func mustHexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func mustHex32Vec(t *testing.T, s string) [32]byte {
	t.Helper()
	b := mustHexBytes(t, s)
	require.Len(t, b, 32)
	var out [32]byte
	copy(out[:], b)
	return out
}
