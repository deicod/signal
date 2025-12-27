package x3dh

import (
	"github.com/deicod/signal/keys"
)

// AssociatedData constructs AD = Encode(IKa) || Encode(IKb).
// For wire compatibility, Encode(IK) is the 33-byte libsignal public key serialization.
func AssociatedData(initiator keys.IdentityKey, responder keys.IdentityKey) []byte {
	ad := make([]byte, 0, 66)
	ad = append(ad, keys.SerializeWirePublicKey(initiator.PublicKey)...)
	ad = append(ad, keys.SerializeWirePublicKey(responder.PublicKey)...)
	return ad
}
