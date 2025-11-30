package ratchet

import (
	"crypto/hmac"
	"crypto/sha256"

	signalcrypto "github.com/deicod/signal/crypto"
)

// KDFChain advances a chain key and produces a message key using HMAC-SHA256.
// newChainKey = HMAC(CK, 0x02); messageKey = HMAC(CK, 0x01)
func KDFChain(chainKey [32]byte) (newChainKey, messageKey [32]byte) {
	newChainKey = hmacSHA256(chainKey[:], []byte{0x02})
	messageKey = hmacSHA256(chainKey[:], []byte{0x01})
	return newChainKey, messageKey
}

// DeriveMessageKeys expands a message key into encryption key, authentication key, and IV.
// Uses HKDF-SHA256 with info "MessageKeys" to derive encKey(32), authKey(32), iv(16).
func DeriveMessageKeys(messageKey [32]byte) (encKey, authKey, iv []byte) {
	info := []byte("MessageKeys")
	okm, _ := signalcrypto.HKDF(messageKey[:], nil, info, 32+32+16)
	encKey = okm[:32]
	authKey = okm[32:64]
	iv = okm[64:80]
	return encKey, authKey, iv
}

func hmacSHA256(key, data []byte) [32]byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	sum := mac.Sum(nil)
	var out [32]byte
	copy(out[:], sum)
	return out
}
