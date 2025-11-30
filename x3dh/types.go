package x3dh

import "github.com/deicod/signal/keys"

// Message is the initial message sent by the initiator.
type Message struct {
	IdentityKey    keys.IdentityKey
	EphemeralKey   [32]byte
	PreKeyID       *uint32
	SignedPreKeyID uint32
	Ciphertext     []byte
}

// Result carries the derived shared secret and associated metadata.
type Result struct {
	SharedSecret   [32]byte
	AssociatedData []byte
	RemoteIdentity keys.IdentityKey
	InitialMessage Message
}
