package x3dh

import (
	"crypto/sha256"

	"github.com/deicod/signal/keys"
)

// AssociatedData constructs the AD = H(initiator identity || responder identity).
func AssociatedData(initiator keys.IdentityKey, responder keys.IdentityKey) []byte {
	h := sha256.New()
	h.Write(initiator.PublicKey[:])
	h.Write(responder.PublicKey[:])
	h.Write(initiator.SigningPublic[:])
	h.Write(responder.SigningPublic[:])
	return h.Sum(nil)
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
