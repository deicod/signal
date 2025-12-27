package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
)

var errAESCTRHMACInvalidCiphertext = errors.New("aes-ctr-hmac: invalid ciphertext")

const aesCTRHMACSize = 10

// AES256CTRHMACSHA256Encrypt encrypts plaintext with AES-256-CTR and appends a truncated HMAC-SHA256.
func AES256CTRHMACSHA256Encrypt(plaintext, cipherKey, macKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		return nil, fmt.Errorf("aes-ctr-hmac: init cipher: %w", err)
	}

	var nonce [aes.BlockSize]byte
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCTR(block, nonce[:]).XORKeyStream(ciphertext, plaintext)

	mac := hmac.New(sha256.New, macKey)
	mac.Write(ciphertext)
	sum := mac.Sum(nil)
	ciphertext = append(ciphertext, sum[:aesCTRHMACSize]...)
	return ciphertext, nil
}

// AES256CTRHMACSHA256Decrypt verifies the truncated HMAC-SHA256 and decrypts AES-256-CTR ciphertext.
func AES256CTRHMACSHA256Decrypt(ciphertext, cipherKey, macKey []byte) ([]byte, error) {
	if len(ciphertext) < aesCTRHMACSize {
		return nil, errAESCTRHMACInvalidCiphertext
	}

	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		return nil, fmt.Errorf("aes-ctr-hmac: init cipher: %w", err)
	}

	msgLen := len(ciphertext) - aesCTRHMACSize
	msg := ciphertext[:msgLen]
	mac := ciphertext[msgLen:]

	sumMac := hmac.New(sha256.New, macKey)
	sumMac.Write(msg)
	calc := sumMac.Sum(nil)
	if subtle.ConstantTimeCompare(calc[:aesCTRHMACSize], mac) != 1 {
		return nil, errAESCTRHMACInvalidCiphertext
	}

	var nonce [aes.BlockSize]byte
	plaintext := make([]byte, msgLen)
	cipher.NewCTR(block, nonce[:]).XORKeyStream(plaintext, msg)
	return plaintext, nil
}
