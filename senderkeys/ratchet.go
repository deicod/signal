package senderkeys

import (
	"encoding/binary"
	"fmt"
	"math"

	signalcrypto "github.com/deicod/signal/crypto"
	signalerrors "github.com/deicod/signal/errors"
)

const (
	senderKeySeedSize = 32

	senderKeyIVSize        = 16
	senderKeyCipherKeySize = 32
	senderKeyHKDFInfo      = "WhisperGroup"

	senderMessageKeySeedConstant = 0x01
	senderChainKeySeedConstant   = 0x02
)

func generateSenderKeyID() (uint32, error) {
	b, err := signalcrypto.RandomBytes(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

func generateSenderKeySeed() ([senderKeySeedSize]byte, error) {
	var seed [senderKeySeedSize]byte
	b, err := signalcrypto.RandomBytes(len(seed))
	if err != nil {
		return seed, err
	}
	copy(seed[:], b)
	return seed, nil
}

func generateDistributionID() ([distributionIDSize]byte, error) {
	var id [distributionIDSize]byte
	b, err := signalcrypto.RandomBytes(len(id))
	if err != nil {
		return id, err
	}
	copy(id[:], b)
	return id, nil
}

func generateSigningKey() (public [32]byte, privateSeed [32]byte, err error) {
	kp, err := signalcrypto.GenerateKeyPair()
	if err != nil {
		return public, privateSeed, err
	}
	return kp.PublicKey, kp.PrivateKey, nil
}

type senderChainKey struct {
	iteration uint32
	seed      [senderKeySeedSize]byte
}

func (k senderChainKey) senderMessageKey() (senderMessageKey, error) {
	seed := k.derive(senderMessageKeySeedConstant)
	return newSenderMessageKey(k.iteration, seed)
}

func (k senderChainKey) next() (senderChainKey, error) {
	if k.iteration == math.MaxUint32 {
		return senderChainKey{}, fmt.Errorf("sender chain key: %w", signalerrors.ErrCounterOverflow)
	}
	return senderChainKey{
		iteration: k.iteration + 1,
		seed:      k.derive(senderChainKeySeedConstant),
	}, nil
}

func (k senderChainKey) derive(constant byte) [senderKeySeedSize]byte {
	derived := signalcrypto.HMAC256(k.seed[:], []byte{constant})
	var out [senderKeySeedSize]byte
	copy(out[:], derived)
	return out
}

type senderMessageKey struct {
	iteration uint32
	seed      [senderKeySeedSize]byte
	iv        [senderKeyIVSize]byte
	cipherKey [senderKeyCipherKeySize]byte
}

func newSenderMessageKey(iteration uint32, seed [senderKeySeedSize]byte) (senderMessageKey, error) {
	derivative, err := signalcrypto.HKDF(seed[:], nil, []byte(senderKeyHKDFInfo), senderKeyIVSize+senderKeyCipherKeySize)
	if err != nil {
		return senderMessageKey{}, err
	}
	var iv [senderKeyIVSize]byte
	copy(iv[:], derivative[:senderKeyIVSize])
	var cipherKey [senderKeyCipherKeySize]byte
	copy(cipherKey[:], derivative[senderKeyIVSize:])
	return senderMessageKey{
		iteration: iteration,
		seed:      seed,
		iv:        iv,
		cipherKey: cipherKey,
	}, nil
}
