package protocol

// CiphertextType distinguishes ciphertext message formats.
type CiphertextType int

const (
	// PreKeyType indicates a ciphertext carrying the X3DH initial message.
	PreKeyType CiphertextType = iota
	// SignalType indicates a standard Double Ratchet ciphertext.
	SignalType
)

// CiphertextMessage represents a serialized ciphertext envelope.
type CiphertextMessage interface {
	Type() CiphertextType
	Serialize() []byte
}
