package spqr

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"

	signalcrypto "github.com/deicod/signal/crypto"
)

const authenticatorMacSize = 32

var (
	authenticatorInfoUpdate = []byte("Signal_PQCKA_V1_MLKEM768:Authenticator Update")
	authenticatorInfoHdr    = []byte("Signal_PQCKA_V1_MLKEM768:ekheader")
	authenticatorInfoCt     = []byte("Signal_PQCKA_V1_MLKEM768:ciphertext")
)

type authenticator struct {
	rootKey []byte
	macKey  []byte
}

func newAuthenticator(rootKey []byte, epoch uint64) *authenticator {
	a := &authenticator{
		rootKey: make([]byte, 32),
		macKey:  make([]byte, 32),
	}
	a.update(epoch, rootKey)
	return a
}

func (a *authenticator) clone() *authenticator {
	if a == nil {
		return nil
	}
	return &authenticator{
		rootKey: append([]byte(nil), a.rootKey...),
		macKey:  append([]byte(nil), a.macKey...),
	}
}

func (a *authenticator) update(epoch uint64, key []byte) error {
	ikm := make([]byte, 0, len(a.rootKey)+len(key))
	ikm = append(ikm, a.rootKey...)
	ikm = append(ikm, key...)
	info := make([]byte, 0, len(authenticatorInfoUpdate)+8)
	info = append(info, authenticatorInfoUpdate...)
	info = append(info, epochBytes(epoch)...)
	okm, err := signalcrypto.HKDF(ikm, make([]byte, 32), info, 64)
	if err != nil {
		return err
	}
	a.rootKey = append(a.rootKey[:0], okm[:32]...)
	a.macKey = append(a.macKey[:0], okm[32:]...)
	return nil
}

func (a *authenticator) macHdr(epoch uint64, hdr []byte) []byte {
	data := make([]byte, 0, len(authenticatorInfoHdr)+8+len(hdr))
	data = append(data, authenticatorInfoHdr...)
	data = append(data, epochBytes(epoch)...)
	data = append(data, hdr...)
	return hmacSha256(a.macKey, data)
}

func (a *authenticator) macCt(epoch uint64, ct []byte) []byte {
	data := make([]byte, 0, len(authenticatorInfoCt)+8+len(ct))
	data = append(data, authenticatorInfoCt...)
	data = append(data, epochBytes(epoch)...)
	data = append(data, ct...)
	return hmacSha256(a.macKey, data)
}

func (a *authenticator) verifyHdr(epoch uint64, hdr []byte, expected []byte) error {
	if len(expected) != authenticatorMacSize {
		return ErrInvalidMessage
	}
	if subtle.ConstantTimeCompare(expected, a.macHdr(epoch, hdr)) != 1 {
		return ErrInvalidMAC
	}
	return nil
}

func (a *authenticator) verifyCt(epoch uint64, ct []byte, expected []byte) error {
	if len(expected) != authenticatorMacSize {
		return ErrInvalidMessage
	}
	if subtle.ConstantTimeCompare(expected, a.macCt(epoch, ct)) != 1 {
		return ErrInvalidMAC
	}
	return nil
}

func hmacSha256(key []byte, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}
