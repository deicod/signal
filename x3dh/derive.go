package x3dh

import (
	"bytes"

	signalcrypto "github.com/deicod/signal/crypto"
)

var (
	legacyInfoString = []byte("X3DH")
	pqInfoString     = []byte("WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024")
	discontinuity    = bytes.Repeat([]byte{0xFF}, 32)
)

func deriveLegacySecret(ikm []byte) ([32]byte, error) {
	var shared [32]byte
	secretBytes, err := signalcrypto.HKDF(ikm, nil, legacyInfoString, 32)
	if err != nil {
		return shared, err
	}
	copy(shared[:], secretBytes)
	signalcrypto.ZeroBytes(secretBytes)
	return shared, nil
}

func derivePQSecret(ikm []byte) (root [32]byte, chain [32]byte, pqr [32]byte, err error) {
	secretBytes, err := signalcrypto.HKDF(ikm, nil, pqInfoString, 96)
	if err != nil {
		return root, chain, pqr, err
	}
	copy(root[:], secretBytes[:32])
	copy(chain[:], secretBytes[32:64])
	copy(pqr[:], secretBytes[64:96])
	signalcrypto.ZeroBytes(secretBytes)
	return root, chain, pqr, nil
}
