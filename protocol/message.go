package protocol

// CiphertextType distinguishes ciphertext message formats.
type CiphertextType int

const (
	PreKeyType CiphertextType = iota
	SignalType
)

// CiphertextMessage represents a serialized ciphertext envelope.
type CiphertextMessage interface {
	Type() CiphertextType
	Serialize() []byte
}
