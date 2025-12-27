package sealedsender

import (
	"fmt"

	"google.golang.org/protobuf/encoding/protowire"

	signalerrors "github.com/deicod/signal/errors"
)

// UnidentifiedSenderMessageContent wraps the inner Signal payload for sealed sender.
type UnidentifiedSenderMessageContent struct {
	serialized   []byte
	sender       *SenderCertificate
	msgType      MessageType
	content      []byte
	contentHint  ContentHint
	groupID      []byte
	groupIDValid bool
}

// ParseUnidentifiedSenderMessageContent parses the protobuf payload for sealed sender content.
func ParseUnidentifiedSenderMessageContent(data []byte) (*UnidentifiedSenderMessageContent, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: sealed sender content empty", signalerrors.ErrInvalidMessage)
	}

	raw := append([]byte(nil), data...)

	var (
		msgType     MessageType
		sender      *SenderCertificate
		content     []byte
		hint        = ContentHintDefault
		groupID     []byte
		gotType     bool
		gotSender   bool
		gotContent  bool
		groupIDSeen bool
	)

	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return nil, fmt.Errorf("%w: sealed sender content tag", signalerrors.ErrInvalidMessage)
		}
		data = data[n:]
		switch num {
		case 1: // type
			if typ != protowire.VarintType {
				return nil, fmt.Errorf("%w: sealed sender type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return nil, fmt.Errorf("%w: sealed sender type", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
			parsed, err := parseMessageType(val)
			if err != nil {
				return nil, err
			}
			msgType = parsed
			gotType = true
		case 2: // sender certificate
			if typ != protowire.BytesType {
				return nil, fmt.Errorf("%w: sealed sender certificate type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, fmt.Errorf("%w: sealed sender certificate", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
			cert, err := ParseSenderCertificate(val)
			if err != nil {
				return nil, err
			}
			sender = cert
			gotSender = true
		case 3: // content
			if typ != protowire.BytesType {
				return nil, fmt.Errorf("%w: sealed sender content type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, fmt.Errorf("%w: sealed sender content", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
			content = append([]byte(nil), val...)
			gotContent = true
		case 4: // content hint
			if typ != protowire.VarintType {
				return nil, fmt.Errorf("%w: sealed sender content hint type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return nil, fmt.Errorf("%w: sealed sender content hint", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
			hint = parseContentHint(val)
		case 5: // group id
			if typ != protowire.BytesType {
				return nil, fmt.Errorf("%w: sealed sender group id type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, fmt.Errorf("%w: sealed sender group id", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
			groupID = append([]byte(nil), val...)
			groupIDSeen = true
		default:
			n := protowire.ConsumeFieldValue(num, typ, data)
			if n < 0 {
				return nil, fmt.Errorf("%w: sealed sender content field", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
		}
	}

	if !gotType || !gotSender || !gotContent {
		return nil, fmt.Errorf("%w: sealed sender content missing fields", signalerrors.ErrInvalidMessage)
	}

	return &UnidentifiedSenderMessageContent{
		serialized:   raw,
		sender:       sender,
		msgType:      msgType,
		content:      content,
		contentHint:  hint,
		groupID:      groupID,
		groupIDValid: groupIDSeen,
	}, nil
}

// NewUnidentifiedSenderMessageContent builds a sealed sender content payload.
func NewUnidentifiedSenderMessageContent(msgType MessageType, sender *SenderCertificate, content []byte, hint ContentHint, groupID []byte) (*UnidentifiedSenderMessageContent, error) {
	if sender == nil {
		return nil, fmt.Errorf("%w: sender certificate is nil", signalerrors.ErrInvalidMessage)
	}
	if _, err := parseMessageType(uint64(msgType)); err != nil {
		return nil, err
	}

	serialized := make([]byte, 0, 64+len(content)+len(groupID))
	serialized = protowire.AppendTag(serialized, 1, protowire.VarintType)
	serialized = protowire.AppendVarint(serialized, uint64(msgType))
	serialized = protowire.AppendTag(serialized, 2, protowire.BytesType)
	serialized = protowire.AppendBytes(serialized, sender.Serialize())
	serialized = protowire.AppendTag(serialized, 3, protowire.BytesType)
	serialized = protowire.AppendBytes(serialized, content)
	if hint != ContentHintDefault {
		serialized = protowire.AppendTag(serialized, 4, protowire.VarintType)
		serialized = protowire.AppendVarint(serialized, uint64(hint))
	}
	if len(groupID) > 0 {
		serialized = protowire.AppendTag(serialized, 5, protowire.BytesType)
		serialized = protowire.AppendBytes(serialized, groupID)
	}

	return &UnidentifiedSenderMessageContent{
		serialized:   serialized,
		sender:       sender,
		msgType:      msgType,
		content:      append([]byte(nil), content...),
		contentHint:  hint,
		groupID:      append([]byte(nil), groupID...),
		groupIDValid: len(groupID) > 0,
	}, nil
}

// Serialize returns the wire encoding of the content.
func (c *UnidentifiedSenderMessageContent) Serialize() []byte {
	if c == nil {
		return nil
	}
	return append([]byte(nil), c.serialized...)
}

// Sender returns the sender certificate.
func (c *UnidentifiedSenderMessageContent) Sender() *SenderCertificate {
	if c == nil {
		return nil
	}
	return c.sender
}

// MessageType returns the wrapped message type.
func (c *UnidentifiedSenderMessageContent) MessageType() MessageType {
	if c == nil {
		return 0
	}
	return c.msgType
}

// Content returns the inner payload.
func (c *UnidentifiedSenderMessageContent) Content() []byte {
	if c == nil {
		return nil
	}
	return append([]byte(nil), c.content...)
}

// ContentHint returns the content hint value.
func (c *UnidentifiedSenderMessageContent) ContentHint() ContentHint {
	if c == nil {
		return ContentHintDefault
	}
	return c.contentHint
}

// GroupID returns the optional group ID, if present.
func (c *UnidentifiedSenderMessageContent) GroupID() ([]byte, bool) {
	if c == nil || !c.groupIDValid {
		return nil, false
	}
	return append([]byte(nil), c.groupID...), true
}
