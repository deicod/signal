package senderkeys

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	signalcrypto "github.com/deicod/signal/crypto"
	"github.com/stretchr/testify/require"
)

type senderKeyVectors struct {
	Distribution distributionVector `json:"distribution_message"`
	Message      messageVector      `json:"sender_key_message"`
	Plaintext    string             `json:"plaintext"`
}

type distributionVector struct {
	Serialized     string `json:"serialized"`
	DistributionID string `json:"distribution_id"`
	ChainID        uint32 `json:"chain_id"`
	Iteration      uint32 `json:"iteration"`
	ChainKey       string `json:"chain_key"`
	SigningPublic  string `json:"signing_public"`
}

type messageVector struct {
	Serialized     string `json:"serialized"`
	DistributionID string `json:"distribution_id"`
	ChainID        uint32 `json:"chain_id"`
	Iteration      uint32 `json:"iteration"`
	Ciphertext     string `json:"ciphertext"`
	Signature      string `json:"signature"`
}

func TestSenderKeyVectors(t *testing.T) {
	files := []string{"senderkeys.json", "senderkeys_libsignal.json"}
	for _, filename := range files {
		t.Run(filename, func(t *testing.T) {
			vec := loadSenderKeyVectors(t, filename)

			distBytes := mustHexBytes(t, vec.Distribution.Serialized)
			msgBytes := mustHexBytes(t, vec.Message.Serialized)

			dist, err := parseDistributionMessage(distBytes)
			require.NoError(t, err)
			require.Equal(t, senderKeyMessageVersion, dist.messageVersion)
			require.Equal(t, vec.Distribution.ChainID, dist.keyID)
			require.Equal(t, vec.Distribution.Iteration, dist.iteration)
			require.Equal(t, mustHex16(t, vec.Distribution.DistributionID), dist.distributionID)
			require.Equal(t, mustHex32(t, vec.Distribution.ChainKey), dist.chainKey)
			require.Equal(t, mustHex32(t, vec.Distribution.SigningPublic), dist.signingPublic)

			msg, signedBytes, err := parseSenderKeyMessage(msgBytes)
			require.NoError(t, err)
			require.Equal(t, senderKeyMessageVersion, msg.messageVersion)
			require.Equal(t, vec.Message.ChainID, msg.keyID)
			require.Equal(t, vec.Message.Iteration, msg.iteration)
			require.Equal(t, mustHex16(t, vec.Message.DistributionID), msg.distributionID)
			require.Equal(t, mustHexBytes(t, vec.Message.Ciphertext), msg.ciphertext)
			require.Equal(t, mustHexBytes(t, vec.Message.Signature), msg.signature[:])

			ok := signalcrypto.XEdDSAVerify(dist.signingPublic, msg.signature[:], signedBytes)
			require.True(t, ok)

			plaintext := decryptSenderKeyVector(t, dist, msg)
			require.Equal(t, mustHexBytes(t, vec.Plaintext), plaintext)
		})
	}
}

func decryptSenderKeyVector(t *testing.T, dist *distributionMessage, msg *senderKeyMessage) []byte {
	t.Helper()
	chainKey := senderChainKey{iteration: dist.iteration, seed: dist.chainKey}
	for chainKey.iteration < msg.iteration {
		next, err := chainKey.next()
		require.NoError(t, err)
		chainKey = next
	}
	messageKey, err := chainKey.senderMessageKey()
	require.NoError(t, err)
	plaintext, err := signalcrypto.AESCBCDecrypt(messageKey.cipherKey[:], messageKey.iv[:], msg.ciphertext)
	require.NoError(t, err)
	return plaintext
}

func loadSenderKeyVectors(t *testing.T, filename string) senderKeyVectors {
	t.Helper()
	path := filepath.Join("..", "testing", "vectors", filename)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)

	var vec senderKeyVectors
	require.NoError(t, json.Unmarshal(raw, &vec))
	return vec
}

func mustHexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func mustHex16(t *testing.T, s string) [distributionIDSize]byte {
	t.Helper()
	b := mustHexBytes(t, s)
	require.Len(t, b, distributionIDSize)
	var out [distributionIDSize]byte
	copy(out[:], b)
	return out
}

func mustHex32(t *testing.T, s string) [32]byte {
	t.Helper()
	b := mustHexBytes(t, s)
	require.Len(t, b, 32)
	var out [32]byte
	copy(out[:], b)
	return out
}
