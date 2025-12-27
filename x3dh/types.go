package x3dh

import (
	signalcrypto "github.com/deicod/signal/crypto"
	"github.com/deicod/signal/keys"
)

// Message is the initial message sent by the initiator.
type Message struct {
	IdentityKey    keys.IdentityKey
	EphemeralKey   [32]byte
	PreKeyID       *uint32
	SignedPreKeyID uint32
	KyberPreKeyID  *uint32
	KyberCiphertext []byte
	Ciphertext     []byte
}

// Result carries the derived shared secret and associated metadata.
type Result struct {
	SharedSecret     [32]byte
	InitialChainKey  *[32]byte
	AssociatedData   []byte
	RemoteIdentity   keys.IdentityKey
	InitialMessage   Message
	LocalEphemeral   *signalcrypto.KeyPair // Ephemeral key used by initiator during X3DH
	LocalRatchetKey  *signalcrypto.KeyPair // Ratchet key material for responder (usually signed pre-key)
	RemoteRatchetKey *[32]byte             // Remote party's ratchet key (responder's signed pre-key)
}
