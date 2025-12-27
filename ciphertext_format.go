package signal

import (
	"encoding/binary"

	wire "github.com/deicod/signal/protocol/wire"
)

// CiphertextFormat identifies the encoding format of a ciphertext.
type CiphertextFormat int

const (
	// CiphertextUnknown indicates the format could not be determined.
	CiphertextUnknown CiphertextFormat = iota
	// CiphertextWire indicates libsignal-compatible wire encoding.
	CiphertextWire
	// CiphertextEnvelope indicates the legacy internal envelope encoding.
	CiphertextEnvelope
)

const (
	legacyEnvelopeVersion    byte = 1
	legacyEnvelopeTypeSignal byte = 1
	legacyEnvelopeTypePreKey byte = 2
)

// DetectCiphertextFormat inspects ciphertext bytes and classifies them as wire or legacy envelope.
func DetectCiphertextFormat(ciphertext []byte) CiphertextFormat {
	if isLegacyEnvelope(ciphertext) {
		return CiphertextEnvelope
	}
	if isWireCiphertext(ciphertext) {
		return CiphertextWire
	}
	return CiphertextUnknown
}

func isLegacyEnvelope(ciphertext []byte) bool {
	if len(ciphertext) < 6 {
		return false
	}
	if ciphertext[0] != legacyEnvelopeVersion {
		return false
	}
	msgType := ciphertext[1]
	if msgType != legacyEnvelopeTypeSignal && msgType != legacyEnvelopeTypePreKey {
		return false
	}
	payloadLen := binary.BigEndian.Uint32(ciphertext[2:6])
	return int(payloadLen) == len(ciphertext)-6
}

func isWireCiphertext(ciphertext []byte) bool {
	if _, err := wire.ParseSignalMessage(ciphertext); err == nil {
		return true
	}
	if _, err := wire.ParsePreKeySignalMessage(ciphertext); err == nil {
		return true
	}
	return false
}
