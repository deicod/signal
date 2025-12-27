package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

var (
	errAESCBCInvalidIV         = errors.New("aes-cbc: invalid iv length")
	errAESCBCInvalidCiphertext = errors.New("aes-cbc: invalid ciphertext length")
	errAESCBCInvalidPadding    = errors.New("aes-cbc: invalid padding")
)

// AESCBCEncrypt encrypts plaintext with AES-CBC and PKCS#7 padding.
func AESCBCEncrypt(key, iv, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes-cbc: init cipher: %w", err)
	}
	if len(iv) != block.BlockSize() {
		return nil, errAESCBCInvalidIV
	}

	padded, err := pkcs7Pad(plaintext, block.BlockSize())
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
	return out, nil
}

// AESCBCDecrypt decrypts ciphertext with AES-CBC and PKCS#7 unpadding.
func AESCBCDecrypt(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes-cbc: init cipher: %w", err)
	}
	if len(iv) != block.BlockSize() {
		return nil, errAESCBCInvalidIV
	}
	if len(ciphertext) == 0 || len(ciphertext)%block.BlockSize() != 0 {
		return nil, errAESCBCInvalidCiphertext
	}

	out := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ciphertext)
	plaintext, err := pkcs7Unpad(out, block.BlockSize())
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func pkcs7Pad(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 || blockSize > 255 {
		return nil, errAESCBCInvalidPadding
	}
	padLen := blockSize - (len(data) % blockSize)
	if padLen == 0 {
		padLen = blockSize
	}
	out := make([]byte, len(data)+padLen)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(padLen)
	}
	return out, nil
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 || blockSize > 255 {
		return nil, errAESCBCInvalidPadding
	}
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errAESCBCInvalidPadding
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > blockSize {
		return nil, errAESCBCInvalidPadding
	}
	if padLen > len(data) {
		return nil, errAESCBCInvalidPadding
	}
	for _, b := range data[len(data)-padLen:] {
		if int(b) != padLen {
			return nil, errAESCBCInvalidPadding
		}
	}
	return data[:len(data)-padLen], nil
}
