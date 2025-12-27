package signal

import (
	"errors"
	"fmt"
)

// Recipient describes a target device for multi-device fanout encryption.
//
// If a session does not yet exist, Bundle can be provided to bootstrap one.
type Recipient struct {
	Address Address
	Bundle  *PreKeyBundle
}

// FanoutCipher encrypts a plaintext to multiple recipient devices, creating sessions as needed.
type FanoutCipher struct {
	store ProtocolStore
}

// NewFanoutCipher constructs a FanoutCipher bound to a ProtocolStore.
func NewFanoutCipher(s ProtocolStore) *FanoutCipher {
	return &FanoutCipher{store: s}
}

// Encrypt encrypts plaintext for each recipient device.
//
// For each recipient, Encrypt first attempts to use an existing session; if no session exists
// and a PreKeyBundle is provided, it will bootstrap a session and encrypt with it.
func (f *FanoutCipher) Encrypt(plaintext []byte, recipients []Recipient) (map[Address][]byte, error) {
	if f == nil || f.store == nil {
		return nil, fmt.Errorf("fanout cipher not initialized")
	}

	out := make(map[Address][]byte, len(recipients))
	for _, recipient := range recipients {
		c := NewCipher(f.store, recipient.Address)
		ciphertext, err := c.Encrypt(plaintext)
		if err != nil {
			if errors.Is(err, ErrNoSession) && recipient.Bundle != nil {
				ciphertext, err = c.EncryptWithPreKeyBundle(recipient.Bundle, plaintext)
			}
		}
		if err != nil {
			return nil, err
		}
		out[recipient.Address] = ciphertext
	}

	return out, nil
}
