package crypto

import (
	"errors"
	"fmt"

	"github.com/ericlagergren/siv"
)

// AESGCMSIVNonceSize is the nonce size for AES-GCM-SIV.
const AESGCMSIVNonceSize = 12

var (
	errAESGCMSIVInvalidNonce      = errors.New("aes-gcm-siv: invalid nonce length")
	errAESGCMSIVInvalidCiphertext = errors.New("aes-gcm-siv: invalid ciphertext")
)

// AESGCMSIVEncrypt encrypts plaintext using AES-GCM-SIV with the provided nonce and associated data.
func AESGCMSIVEncrypt(key, nonce, plaintext, associatedData []byte) ([]byte, error) {
	if len(nonce) != AESGCMSIVNonceSize {
		return nil, errAESGCMSIVInvalidNonce
	}
	aead, err := siv.NewGCM(key)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm-siv: init: %w", err)
	}
	return aead.Seal(nil, nonce, plaintext, associatedData), nil
}

// AESGCMSIVDecrypt decrypts ciphertext using AES-GCM-SIV with the provided nonce and associated data.
func AESGCMSIVDecrypt(key, nonce, ciphertext, associatedData []byte) ([]byte, error) {
	if len(nonce) != AESGCMSIVNonceSize {
		return nil, errAESGCMSIVInvalidNonce
	}
	aead, err := siv.NewGCM(key)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm-siv: init: %w", err)
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, associatedData)
	if err != nil {
		return nil, errAESGCMSIVInvalidCiphertext
	}
	return plaintext, nil
}
