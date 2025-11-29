package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
)

// HMAC256 returns HMAC-SHA256(key, data).
func HMAC256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// HMAC512 returns HMAC-SHA512(key, data).
func HMAC512(key, data []byte) []byte {
	mac := hmac.New(sha512.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// HMACVerify computes HMAC-SHA256 over data and compares it to expectedMAC
// in constant time. Returns false if lengths differ.
func HMACVerify(key, data, expectedMAC []byte) bool {
	actual := HMAC256(key, data)
	if len(actual) != len(expectedMAC) {
		return false
	}
	return subtle.ConstantTimeCompare(actual, expectedMAC) == 1
}
