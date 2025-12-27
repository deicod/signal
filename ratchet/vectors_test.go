package ratchet

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	signalcrypto "github.com/deicod/signal/crypto"
	"github.com/deicod/signal/keys"
	"github.com/deicod/signal/store/memory"
	"github.com/deicod/signal/x3dh"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
)

type ratchetVectorFile struct {
	X3DH                ratchetX3DHInput   `json:"x3dh"`
	AssociatedData      string             `json:"associated_data"`
	InitiatorMessages   []ratchetVectorMsg `json:"initiator_messages"`
	ResponderMessages   []ratchetVectorMsg `json:"responder_messages"`
	DeliveryToResponder []int              `json:"delivery_to_responder"`
	DeliveryToInitiator []int              `json:"delivery_to_initiator"`
}

type ratchetX3DHInput struct {
	Initiator            x3dhInitiatorInput `json:"initiator"`
	Responder            x3dhResponderInput `json:"responder"`
	ResponderSendPrivate string             `json:"responder_send_private"`
	SharedSecret         string             `json:"shared_secret"`
}

type ratchetVectorMsg struct {
	Plaintext  string `json:"plaintext"`
	Header     string `json:"header"`
	Ciphertext string `json:"ciphertext"`
}

func TestRatchetVectors(t *testing.T) {
	vec := loadRatchetVectors(t)

	initID := identityFromPrivateHex(t, vec.X3DH.Initiator.IdentityPrivate)
	respID := identityFromPrivateHex(t, vec.X3DH.Responder.IdentityPrivate)
	initEph := keyPairFromPrivateHex(t, vec.X3DH.Initiator.EphemeralPrivate)

	signedKP := keyPairFromPrivateHex(t, vec.X3DH.Responder.SignedPreKeyPrivate)
	signedSig := mustHexBytes(t, vec.X3DH.Responder.SignedPreKeySignature)
	signedPreKey := &keys.SignedPreKey{
		ID:        vec.X3DH.Responder.SignedPreKeyID,
		KeyPair:   signedKP,
		Signature: signedSig,
	}

	preKP := keyPairFromPrivateHex(t, vec.X3DH.Responder.PreKeyPrivate)
	preKey := &keys.PreKey{ID: *vec.X3DH.Responder.PreKeyID, KeyPair: preKP}

	bundle, err := keys.NewPreKeyBundle(99, 1, preKey, signedPreKey, respID.PublicKey)
	require.NoError(t, err)

	initiator := x3dh.NewInitiatorWithGenerator(initID, func() (*signalcrypto.KeyPair, error) {
		return initEph, nil
	})
	initRes, err := initiator.ProcessPreKeyBundle(bundle)
	require.NoError(t, err)
	require.Equal(t, mustHex32Vec(t, vec.X3DH.SharedSecret), initRes.SharedSecret)

	store := memory.NewStore(respID, 99)
	require.NoError(t, store.StorePreKey(preKey.ID, preKey))

	responder := x3dh.NewResponder(respID, signedPreKey, store, store)
	respRes, err := responder.ProcessInitialMessage(&initRes.InitialMessage)
	require.NoError(t, err)

	sendDH := keyPairFromPrivateHex(t, vec.X3DH.ResponderSendPrivate)
	gen := func() (*signalcrypto.KeyPair, error) {
		kp := *sendDH
		return &kp, nil
	}

	initState, err := InitializeStateWithGenerator(initRes, true, gen)
	require.NoError(t, err)
	respState, err := InitializeStateWithGenerator(respRes, false, gen)
	require.NoError(t, err)

	ad := mustHexBytes(t, vec.AssociatedData)
	require.Equal(t, ad, initRes.AssociatedData)
	require.Equal(t, ad, respRes.AssociatedData)

	initSend := initState.Clone()
	initRecv := initState.Clone()
	respSend := respState.Clone()
	respRecv := respState.Clone()

	for i, msg := range vec.InitiatorMessages {
		pt := mustHexBytes(t, msg.Plaintext)
		enc, err := initSend.Encrypt(pt, ad)
		require.NoError(t, err)
		require.Equal(t, mustHexBytes(t, msg.Header), enc.Header.Serialize(), "initiator message %d header", i)
		require.Equal(t, mustHexBytes(t, msg.Ciphertext), enc.Ciphertext, "initiator message %d ciphertext", i)
	}

	for i, msg := range vec.ResponderMessages {
		pt := mustHexBytes(t, msg.Plaintext)
		enc, err := respSend.Encrypt(pt, ad)
		require.NoError(t, err)
		require.Equal(t, mustHexBytes(t, msg.Header), enc.Header.Serialize(), "responder message %d header", i)
		require.Equal(t, mustHexBytes(t, msg.Ciphertext), enc.Ciphertext, "responder message %d ciphertext", i)
	}

	for _, idx := range vec.DeliveryToResponder {
		msg := vec.InitiatorMessages[idx]
		plain := decryptVectorMessage(t, respRecv, ad, msg)
		require.Equal(t, mustHexBytes(t, msg.Plaintext), plain)
	}

	for _, idx := range vec.DeliveryToInitiator {
		msg := vec.ResponderMessages[idx]
		plain := decryptVectorMessage(t, initRecv, ad, msg)
		require.Equal(t, mustHexBytes(t, msg.Plaintext), plain)
	}
}

func loadRatchetVectors(t *testing.T) ratchetVectorFile {
	t.Helper()
	path := filepath.Join("..", "testing", "vectors", "ratchet.json")
	raw, err := os.ReadFile(path)
	require.NoError(t, err)

	var vec ratchetVectorFile
	require.NoError(t, json.Unmarshal(raw, &vec))
	return vec
}

func decryptVectorMessage(t *testing.T, state *State, ad []byte, msg ratchetVectorMsg) []byte {
	t.Helper()
	headerBytes := mustHexBytes(t, msg.Header)
	header, err := DeserializeHeader(headerBytes)
	require.NoError(t, err)
	wire := &Message{
		Header:     *header,
		Ciphertext: mustHexBytes(t, msg.Ciphertext),
	}
	plaintext, err := state.Decrypt(wire, ad)
	require.NoError(t, err)
	return plaintext
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
