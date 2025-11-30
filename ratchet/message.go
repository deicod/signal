package ratchet

import (
	"errors"
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
	if s == nil {
		return nil, errors.New("encrypt: state is nil")
	}
	if s.DHs == nil {
		return nil, fmt.Errorf("encrypt: missing sending DH key")
	}
	if s.CKs == ([32]byte{}) {
		return nil, fmt.Errorf("encrypt: missing sending chain key")
	}

	header := Header{
		DH: s.DHs.PublicKey,
		PN: s.PN,
		N:  s.Ns,
	}

	newCKs, mk := KDFChain(s.CKs)
	s.CKs = newCKs
	s.Ns++

	encKey, _, _ := DeriveMessageKeys(mk)
	ad := messageAD(associatedData, &header)

	ciphertext, nonce, err := signalcrypto.AESGCMEncrypt(encKey, plaintext, ad)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	return &Message{
		Header:     header,
		Ciphertext: append(nonce, ciphertext...),
	}, nil
}

// Decrypt consumes an incoming message, handling skipped keys and advancing receive state.
func (s *State) Decrypt(msg *Message, associatedData []byte) ([]byte, error) {
	if msg == nil {
		return nil, fmt.Errorf("decrypt: message is nil")
	}

	if s == nil {
		return nil, fmt.Errorf("decrypt: state is nil")
	}

	if mk, ok := s.trySkippedMessageKey(&msg.Header); ok {
		return decryptWithMessageKey(mk, msg, associatedData)
	}

	if s.DHr == nil || *s.DHr != msg.Header.DH {
		if err := s.skipMessageKeys(msg.Header.PN); err != nil {
			return nil, err
		}
		if err := s.DHRatchet(msg.Header.DH); err != nil {
			return nil, err
		}
	}

	if err := s.skipMessageKeys(msg.Header.N); err != nil {
		return nil, err
	}

	if s.CKr == ([32]byte{}) {
		return nil, fmt.Errorf("decrypt: missing receiving chain key")
	}

	newCKr, mk := KDFChain(s.CKr)
	s.CKr = newCKr
	s.Nr++

	return decryptWithMessageKey(&mk, msg, associatedData)
}

func messageAD(associatedData []byte, header *Header) []byte {
	ad := append([]byte{}, associatedData...)
	return append(ad, header.Serialize()...)
}

func decryptWithMessageKey(mk *[32]byte, msg *Message, associatedData []byte) ([]byte, error) {
	encKey, _, _ := DeriveMessageKeys(*mk)
	if len(msg.Ciphertext) < 12 {
		return nil, fmt.Errorf("decrypt: ciphertext too short")
	}
	nonce := msg.Ciphertext[:12]
	body := msg.Ciphertext[12:]
	ad := messageAD(associatedData, &msg.Header)

	plaintext, err := signalcrypto.AESGCMDecrypt(encKey, body, nonce, ad)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}
