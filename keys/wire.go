package keys

import (
	"fmt"

	signalerrors "github.com/deicod/signal/errors"
)

const wireKeyTypeDjb byte = 0x05

// SerializeWirePublicKey returns the libsignal wire serialization of a Curve25519 public key.
// The format is key-type byte (0x05) followed by the 32-byte public key.
func SerializeWirePublicKey(pub [32]byte) []byte {
	out := make([]byte, 1+32)
	out[0] = wireKeyTypeDjb
	copy(out[1:], pub[:])
	return out
}

// DeserializeWirePublicKey parses a libsignal wire-serialized Curve25519 public key.
func DeserializeWirePublicKey(data []byte) ([32]byte, error) {
	var out [32]byte
	if len(data) != 1+32 {
		return out, fmt.Errorf("%w: wire public key length %d", signalerrors.ErrInvalidKey, len(data))
	}
	if data[0] != wireKeyTypeDjb {
		return out, fmt.Errorf("%w: unsupported wire key type 0x%02x", signalerrors.ErrInvalidKey, data[0])
	}
	copy(out[:], data[1:])
	return out, nil
}
