package ratchet

import (
	"fmt"

	signalcrypto "github.com/deicod/signal/crypto"
)

// Message holds an encrypted payload and header.
type Message struct {
	Header     Header
	Ciphertext []byte
}

// Encrypt takes plaintext and associated data, advancing the sending chain.
func (s *State) Encrypt(plaintext, associatedData []byte) (*Message, error) {
	if s.DHs == nil {
		return nil, fmt.Errorf("encrypt: missing sending DH key")
	}
	// Perform send-side ratchet if needed.
	if err := s.RatchetOnSend(); err != nil {
		return nil, err
	}

	// Derive next chain key and message key.
	newCKs, mk := KDFChain(s.CKs)
	s.CKs = newCKs
	encKey, _, _ := DeriveMessageKeys(mk)

	header := Header{
		DH: s.DHs.PublicKey,
		PN: s.PN,
		N:  s.Ns,
	}
	s.Ns++

	// Encrypt payload (use AES-GCM via crypto package).
	ciphertext, nonce, err := signalcrypto.AESGCMEncrypt(encKey, plaintext, append(associatedData, header.Serialize()...))
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	// Prepend nonce to ciphertext
	ctWithNonce := append(nonce, ciphertext...)

	return &Message{
		Header:     header,
		Ciphertext: ctWithNonce,
	}, nil
}
