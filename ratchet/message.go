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

// Decrypt consumes an incoming message, handling skipped keys and advancing receive state.
func (s *State) Decrypt(msg *Message, associatedData []byte) ([]byte, error) {
	if msg == nil {
		return nil, fmt.Errorf("decrypt: message is nil")
	}

	// Try skipped message keys first.
	if pt, ok := s.trySkipped(msg, associatedData); ok {
		return pt, nil
	}

	// If header DH differs, perform a DH ratchet.
	if s.DHr == nil || *s.DHr != msg.Header.DH {
		if err := s.skipMessages(msg.Header.PN); err != nil {
			return nil, err
		}
		if err := s.DHRatchet(msg.Header.DH); err != nil {
			return nil, err
		}
	}

	// Skip until current message number.
	if err := s.skipMessages(msg.Header.N); err != nil {
		return nil, err
	}

	// Derive message key for this message.
	newCKr, mk := KDFChain(s.CKr)
	s.CKr = newCKr
	s.Nr++

	encKey, _, _ := DeriveMessageKeys(mk)
	ad := append(append([]byte{}, associatedData...), msg.Header.Serialize()...)

	if len(msg.Ciphertext) < 12 {
		return nil, fmt.Errorf("decrypt: ciphertext too short")
	}
	nonce := msg.Ciphertext[:12]
	body := msg.Ciphertext[12:]

	plaintext, err := signalcrypto.AESGCMDecrypt(encKey, body, nonce, ad)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}

// trySkipped attempts decryption using previously stored skipped keys.
func (s *State) trySkipped(msg *Message, associatedData []byte) ([]byte, bool) {
	key := SkippedKey{PublicKey: msg.Header.DH, N: msg.Header.N}
	mk, ok := s.MKSkipped[key]
	if !ok {
		return nil, false
	}
	delete(s.MKSkipped, key)
	encKey, _, _ := DeriveMessageKeys(mk)
	ad := append(append([]byte{}, associatedData...), msg.Header.Serialize()...)
	if len(msg.Ciphertext) < 12 {
		return nil, false
	}
	nonce := msg.Ciphertext[:12]
	body := msg.Ciphertext[12:]
	pt, err := signalcrypto.AESGCMDecrypt(encKey, body, nonce, ad)
	if err != nil {
		return nil, false
	}
	return pt, true
}

// skipMessages saves skipped message keys up to (but not including) target.
func (s *State) skipMessages(target uint32) error {
	for s.Nr < target {
		newCKr, mk := KDFChain(s.CKr)
		s.CKr = newCKr
		if s.DHr == nil {
			return fmt.Errorf("skipMessages: missing DHr")
		}
		key := SkippedKey{PublicKey: *s.DHr, N: s.Nr}
		s.MKSkipped[key] = mk
		s.Nr++
	}
	return nil
}
