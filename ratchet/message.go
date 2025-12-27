package ratchet

import (
	"errors"
	"fmt"
	"math"

	signalcrypto "github.com/deicod/signal/crypto"
	signalerrors "github.com/deicod/signal/errors"
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
	if s.Ns == math.MaxUint32 {
		return nil, fmt.Errorf("%w: send counter overflow", signalerrors.ErrCounterOverflow)
	}

	header := Header{
		DH: s.DHs.PublicKey,
		PN: s.PN,
		N:  s.Ns,
	}

	newCKs, mk := KDFChain(s.CKs)
	s.CKs = newCKs
	s.Ns++

	encKey, _, iv := DeriveMessageKeys(mk)
	nonce := iv[:12]
	ad := messageAD(associatedData, &header)

	ciphertext, err := signalcrypto.AESGCMEncryptWithNonce(encKey, plaintext, nonce, ad)
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

	if key, ok := skippedKeyForHeader(&msg.Header); ok {
		if mk, ok := s.MKSkipped[key]; ok {
			plaintext, err := decryptWithMessageKey(&mk, msg, associatedData)
			if err != nil {
				return nil, err
			}
			delete(s.MKSkipped, key)
			return plaintext, nil
		}
	}

	next := s.Clone()

	if next.DHr != nil && msg.Header.DH == *next.DHr && msg.Header.N < next.Nr {
		return nil, fmt.Errorf("%w: message already processed", signalerrors.ErrDuplicateMessage)
	}

	if next.DHr != nil && msg.Header.DH != *next.DHr {
		if _, ok := next.SeenDH[msg.Header.DH]; ok {
			return nil, fmt.Errorf("%w: message for previous ratchet key", signalerrors.ErrDuplicateMessage)
		}
	}

	if next.DHr == nil || *next.DHr != msg.Header.DH {
		if err := next.skipMessageKeys(msg.Header.PN); err != nil {
			return nil, err
		}
		if err := next.DHRatchet(msg.Header.DH); err != nil {
			return nil, err
		}
	}

	if err := next.skipMessageKeys(msg.Header.N); err != nil {
		return nil, err
	}

	if next.CKr == ([32]byte{}) {
		return nil, fmt.Errorf("decrypt: missing receiving chain key")
	}
	if next.Nr == math.MaxUint32 {
		return nil, fmt.Errorf("%w: receive counter overflow", signalerrors.ErrCounterOverflow)
	}

	newCKr, mk := KDFChain(next.CKr)
	next.CKr = newCKr
	next.Nr++

	plaintext, err := decryptWithMessageKey(&mk, msg, associatedData)
	if err != nil {
		return nil, err
	}
	*s = *next
	return plaintext, nil
}

func messageAD(associatedData []byte, header *Header) []byte {
	ad := append([]byte{}, associatedData...)
	return append(ad, header.Serialize()...)
}

func decryptWithMessageKey(mk *[32]byte, msg *Message, associatedData []byte) ([]byte, error) {
	encKey, _, _ := DeriveMessageKeys(*mk)
	if len(msg.Ciphertext) < 12 {
		return nil, fmt.Errorf("%w: decrypt ciphertext too short", signalerrors.ErrInvalidMessage)
	}
	nonce := msg.Ciphertext[:12]
	body := msg.Ciphertext[12:]
	ad := messageAD(associatedData, &msg.Header)

	plaintext, err := signalcrypto.AESGCMDecrypt(encKey, body, nonce, ad)
	if err != nil {
		return nil, errors.Join(signalerrors.ErrInvalidMAC, fmt.Errorf("decrypt: %w", err))
	}
	return plaintext, nil
}
