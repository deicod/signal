package spqr

import "fmt"

// MessageType defines the SPQR message payload variant.
type MessageType uint8

const (
	// MessageTypeNone indicates an empty payload.
	MessageTypeNone MessageType = 0
	// MessageTypeHdr carries a header chunk.
	MessageTypeHdr MessageType = 1
	// MessageTypeEk carries an encapsulation key chunk.
	MessageTypeEk MessageType = 2
	// MessageTypeEkCt1Ack carries an EK chunk and CT1 ack.
	MessageTypeEkCt1Ack MessageType = 3
	// MessageTypeCt1Ack carries a CT1 ack.
	MessageTypeCt1Ack MessageType = 4
	// MessageTypeCt1 carries a ciphertext1 chunk.
	MessageTypeCt1 MessageType = 5
	// MessageTypeCt2 carries a ciphertext2 chunk.
	MessageTypeCt2 MessageType = 6
)

type messagePayload struct {
	kind  MessageType
	chunk *chunk
	ack   bool
}

type v1Message struct {
	epoch   uint64
	payload messagePayload
}

// Message represents a parsed SPQR message.
type Message struct {
	Version    Version
	Epoch      uint64
	Index      uint32
	Type       MessageType
	ChunkIndex uint32
	ChunkData  []byte
}

func (m v1Message) serialize(index uint32) []byte {
	out := make([]byte, 0, 40)
	out = append(out, byte(VersionV1))
	encodeVarint(m.epoch, &out)
	encodeVarint(uint64(index), &out)
	out = append(out, byte(m.payload.kind))
	if hasChunk(m.payload.kind) {
		if m.payload.chunk == nil {
			return out
		}
		encodeVarint(uint64(m.payload.chunk.index), &out)
		out = append(out, m.payload.chunk.data[:]...)
	}
	return out
}

func deserializeV1Message(data []byte) (v1Message, uint32, int, error) {
	if len(data) == 0 || Version(data[0]) != VersionV1 {
		return v1Message{}, 0, 0, ErrInvalidMessage
	}
	pos := 1
	epoch, err := consumeVarint(data, &pos)
	if err != nil {
		return v1Message{}, 0, 0, fmt.Errorf("%w: epoch", ErrInvalidMessage)
	}
	index, err := consumeVarint(data, &pos)
	if err != nil {
		return v1Message{}, 0, 0, fmt.Errorf("%w: index", ErrInvalidMessage)
	}
	if pos >= len(data) {
		return v1Message{}, 0, 0, fmt.Errorf("%w: message type", ErrInvalidMessage)
	}
	msgType := MessageType(data[pos])
	pos++
	payload := messagePayload{kind: msgType}
	if hasChunk(msgType) {
		chunkIndex, err := consumeVarint(data, &pos)
		if err != nil {
			return v1Message{}, 0, 0, fmt.Errorf("%w: chunk index", ErrInvalidMessage)
		}
		if pos+polyChunkDataSize > len(data) {
			return v1Message{}, 0, 0, fmt.Errorf("%w: chunk data", ErrInvalidMessage)
		}
		var dataChunk chunk
		dataChunk.index = uint16(chunkIndex)
		copy(dataChunk.data[:], data[pos:pos+polyChunkDataSize])
		pos += polyChunkDataSize
		payload.chunk = &dataChunk
	}
	msg := v1Message{epoch: epoch, payload: payload}
	return msg, uint32(index), pos, nil
}

// ParseMessage parses an SPQR message from wire bytes.
func ParseMessage(data []byte) (*Message, error) {
	if len(data) == 0 {
		return nil, ErrInvalidMessage
	}
	version := Version(data[0])
	if version == VersionDisabled {
		return &Message{Version: version}, nil
	}
	if version != VersionV1 {
		return nil, ErrUnsupportedVersion
	}
	msg, idx, _, err := deserializeV1Message(data)
	if err != nil {
		return nil, err
	}
	out := &Message{
		Version: version,
		Epoch:   msg.epoch,
		Index:   idx,
		Type:    msg.payload.kind,
	}
	if msg.payload.chunk != nil {
		out.ChunkIndex = uint32(msg.payload.chunk.index)
		out.ChunkData = append([]byte(nil), msg.payload.chunk.data[:]...)
	}
	return out, nil
}

func hasChunk(t MessageType) bool {
	switch t {
	case MessageTypeHdr, MessageTypeEk, MessageTypeEkCt1Ack, MessageTypeCt1, MessageTypeCt2:
		return true
	default:
		return false
	}
}

func encodeVarint(v uint64, out *[]byte) {
	for i := 0; i < 10; i++ {
		b := byte(v & 0x7f)
		if v < 0x80 {
			*out = append(*out, b)
			return
		}
		*out = append(*out, b|0x80)
		v >>= 7
	}
}

func consumeVarint(data []byte, idx *int) (uint64, error) {
	var x uint64
	var s uint
	for {
		if *idx >= len(data) {
			return 0, ErrInvalidMessage
		}
		b := data[*idx]
		*idx += 1
		if b < 0x80 {
			if s >= 64 {
				return 0, ErrInvalidMessage
			}
			return x | uint64(b)<<s, nil
		}
		x |= uint64(b&0x7f) << s
		s += 7
	}
}
