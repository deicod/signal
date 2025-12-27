package sealedsender

import (
	"fmt"

	signalerrors "github.com/deicod/signal/errors"
)

// MessageType identifies the encrypted payload inside a sealed sender message.
type MessageType uint32

const (
	// MessageTypePreKey wraps a PreKeySignalMessage payload.
	MessageTypePreKey MessageType = 1
	// MessageTypeSignal wraps a SignalMessage payload.
	MessageTypeSignal MessageType = 2
	// MessageTypeSenderKey wraps a SenderKeyMessage payload.
	MessageTypeSenderKey MessageType = 7
	// MessageTypePlaintext wraps a plaintext content payload (non-cryptographic).
	MessageTypePlaintext MessageType = 8
)

func parseMessageType(raw uint64) (MessageType, error) {
	switch MessageType(raw) {
	case MessageTypePreKey, MessageTypeSignal, MessageTypeSenderKey, MessageTypePlaintext:
		return MessageType(raw), nil
	default:
		return 0, fmt.Errorf("%w: unsupported message type %d", signalerrors.ErrInvalidMessage, raw)
	}
}

// ContentHint indicates how the recipient should treat delivery errors.
type ContentHint uint32

const (
	// ContentHintDefault indicates the sender will not retry.
	ContentHintDefault ContentHint = 0
	// ContentHintResendable indicates the sender may retry delivery.
	ContentHintResendable ContentHint = 1
	// ContentHintImplicit indicates the message is implicit (e.g., typing indicators).
	ContentHintImplicit ContentHint = 2
)

func parseContentHint(raw uint64) ContentHint {
	switch ContentHint(raw) {
	case ContentHintDefault, ContentHintResendable, ContentHintImplicit:
		return ContentHint(raw)
	default:
		return ContentHint(raw)
	}
}
