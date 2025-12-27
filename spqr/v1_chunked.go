package spqr

// Chunked send_ek states.
type chunkedKeysUnsampled struct {
	uc *unchunkedKeysUnsampled
}

type chunkedKeysSampled struct {
	uc         *unchunkedHeaderSent
	sendingHdr *polyEncoder
}

type chunkedHeaderSent struct {
	uc           *unchunkedEkSent
	sendingEk    *polyEncoder
	receivingCt1 *polyDecoder
}

type chunkedCt1Received struct {
	uc        *unchunkedEkSentCt1Received
	sendingEk *polyEncoder
}

type chunkedEkSentCt1Received struct {
	uc           *unchunkedEkSentCt1Received
	receivingCt2 *polyDecoder
}

// Chunked send_ct states.
type chunkedNoHeaderReceived struct {
	uc           *unchunkedNoHeaderReceived
	receivingHdr *polyDecoder
}

type chunkedHeaderReceived struct {
	uc          *unchunkedHeaderReceived
	receivingEk *polyDecoder
}

type chunkedCt1Sampled struct {
	uc          *unchunkedCt1Sent
	sendingCt1  *polyEncoder
	receivingEk *polyDecoder
}

type chunkedEkReceivedCt1Sampled struct {
	uc         *unchunkedCt1SentEkReceived
	sendingCt1 *polyEncoder
}

type chunkedCt1Acknowledged struct {
	uc          *unchunkedCt1Sent
	receivingEk *polyDecoder
}

type chunkedCt2Sampled struct {
	uc         *unchunkedCt2Sent
	sendingCt2 *polyEncoder
}

type v1States struct {
	state any
}

type v1Send struct {
	msg   v1Message
	key   *epochSecret
	state *v1States
}

type v1Recv struct {
	key   *epochSecret
	state *v1States
}

func initV1StateA(authKey []byte) (*v1States, error) {
	uc, err := newUnchunkedKeysUnsampled(authKey)
	if err != nil {
		return nil, err
	}
	return &v1States{state: &chunkedKeysUnsampled{uc: uc}}, nil
}

func initV1StateB(authKey []byte) (*v1States, error) {
	uc, err := newUnchunkedNoHeaderReceived(authKey)
	if err != nil {
		return nil, err
	}
	dec, err := newPolyDecoder(mlkemHeaderSize + authenticatorMacSize)
	if err != nil {
		return nil, err
	}
	return &v1States{state: &chunkedNoHeaderReceived{uc: uc, receivingHdr: dec}}, nil
}

func (s *v1States) send() (v1Send, error) {
	switch st := s.state.(type) {
	case *chunkedKeysUnsampled:
		next, c, err := st.sendHdrChunk()
		if err != nil {
			return v1Send{}, err
		}
		msg := v1Message{epoch: st.epoch(), payload: messagePayload{kind: MessageTypeHdr, chunk: &c}}
		return v1Send{msg: msg, state: &v1States{state: next}}, nil
	case *chunkedKeysSampled:
		next, c := st.sendHdrChunk()
		msg := v1Message{epoch: st.epoch(), payload: messagePayload{kind: MessageTypeHdr, chunk: &c}}
		return v1Send{msg: msg, state: &v1States{state: next}}, nil
	case *chunkedHeaderSent:
		next, c := st.sendEkChunk()
		msg := v1Message{epoch: st.epoch(), payload: messagePayload{kind: MessageTypeEk, chunk: &c}}
		return v1Send{msg: msg, state: &v1States{state: next}}, nil
	case *chunkedCt1Received:
		next, c := st.sendEkChunk()
		msg := v1Message{epoch: st.epoch(), payload: messagePayload{kind: MessageTypeEkCt1Ack, chunk: &c}}
		return v1Send{msg: msg, state: &v1States{state: next}}, nil
	case *chunkedEkSentCt1Received:
		msg := v1Message{epoch: st.epoch(), payload: messagePayload{kind: MessageTypeCt1Ack, ack: true}}
		return v1Send{msg: msg, state: &v1States{state: st}}, nil
	case *chunkedNoHeaderReceived:
		msg := v1Message{epoch: st.epoch(), payload: messagePayload{kind: MessageTypeNone}}
		return v1Send{msg: msg, state: &v1States{state: st}}, nil
	case *chunkedHeaderReceived:
		next, c, key, err := st.sendCt1Chunk()
		if err != nil {
			return v1Send{}, err
		}
		msg := v1Message{epoch: st.epoch(), payload: messagePayload{kind: MessageTypeCt1, chunk: &c}}
		return v1Send{msg: msg, key: key, state: &v1States{state: next}}, nil
	case *chunkedCt1Sampled:
		next, c := st.sendCt1Chunk()
		msg := v1Message{epoch: st.epoch(), payload: messagePayload{kind: MessageTypeCt1, chunk: &c}}
		return v1Send{msg: msg, state: &v1States{state: next}}, nil
	case *chunkedEkReceivedCt1Sampled:
		next, c := st.sendCt1Chunk()
		msg := v1Message{epoch: st.epoch(), payload: messagePayload{kind: MessageTypeCt1, chunk: &c}}
		return v1Send{msg: msg, state: &v1States{state: next}}, nil
	case *chunkedCt1Acknowledged:
		msg := v1Message{epoch: st.epoch(), payload: messagePayload{kind: MessageTypeNone}}
		return v1Send{msg: msg, state: &v1States{state: st}}, nil
	case *chunkedCt2Sampled:
		next, c := st.sendCt2Chunk()
		msg := v1Message{epoch: st.epoch(), payload: messagePayload{kind: MessageTypeCt2, chunk: &c}}
		return v1Send{msg: msg, state: &v1States{state: next}}, nil
	default:
		return v1Send{}, ErrStateDecode
	}
}

func (s *v1States) recv(msg *v1Message) (v1Recv, error) {
	switch st := s.state.(type) {
	case *chunkedKeysUnsampled:
		return st.recv(msg)
	case *chunkedKeysSampled:
		return st.recv(msg)
	case *chunkedHeaderSent:
		return st.recv(msg)
	case *chunkedCt1Received:
		return st.recv(msg)
	case *chunkedEkSentCt1Received:
		return st.recv(msg)
	case *chunkedNoHeaderReceived:
		return st.recv(msg)
	case *chunkedHeaderReceived:
		return st.recv(msg)
	case *chunkedCt1Sampled:
		return st.recv(msg)
	case *chunkedEkReceivedCt1Sampled:
		return st.recv(msg)
	case *chunkedCt1Acknowledged:
		return st.recv(msg)
	case *chunkedCt2Sampled:
		return st.recv(msg)
	default:
		return v1Recv{}, ErrStateDecode
	}
}

func (s *chunkedKeysUnsampled) epoch() uint64 { return s.uc.epoch }

func (s *chunkedKeysUnsampled) sendHdrChunk() (*chunkedKeysSampled, chunk, error) {
	uc, hdr, mac, err := s.uc.sendHeader()
	if err != nil {
		return nil, chunk{}, err
	}
	payload := append(append([]byte(nil), hdr...), mac...)
	enc, err := newPolyEncoder(payload)
	if err != nil {
		return nil, chunk{}, err
	}
	c := enc.nextChunk()
	return &chunkedKeysSampled{uc: uc, sendingHdr: enc}, c, nil
}

func (s *chunkedKeysUnsampled) recv(msg *v1Message) (v1Recv, error) {
	if msg.epoch > s.epoch() {
		return v1Recv{}, ErrEpochOutOfRange
	}
	return v1Recv{state: &v1States{state: s}}, nil
}

func (s *chunkedKeysSampled) epoch() uint64 { return s.uc.epoch }

func (s *chunkedKeysSampled) sendHdrChunk() (*chunkedKeysSampled, chunk) {
	c := s.sendingHdr.nextChunk()
	return s, c
}

func (s *chunkedKeysSampled) recv(msg *v1Message) (v1Recv, error) {
	switch {
	case msg.epoch > s.epoch():
		return v1Recv{}, ErrEpochOutOfRange
	case msg.epoch < s.epoch():
		return v1Recv{state: &v1States{state: s}}, nil
	default:
		if msg.payload.kind == MessageTypeCt1 && msg.payload.chunk != nil {
			next, err := s.recvCt1Chunk(msg.epoch, msg.payload.chunk)
			if err != nil {
				return v1Recv{}, err
			}
			return v1Recv{state: &v1States{state: next}}, nil
		}
		return v1Recv{state: &v1States{state: s}}, nil
	}
}

func (s *chunkedKeysSampled) recvCt1Chunk(epoch uint64, c *chunk) (*chunkedHeaderSent, error) {
	dec, err := newPolyDecoder(mlkemCiphertext1Size)
	if err != nil {
		return nil, err
	}
	dec.addChunk(c)
	uc, ek := s.uc.sendEk()
	enc, err := newPolyEncoder(ek)
	if err != nil {
		return nil, err
	}
	return &chunkedHeaderSent{uc: uc, sendingEk: enc, receivingCt1: dec}, nil
}

func (s *chunkedHeaderSent) epoch() uint64 { return s.uc.epoch }

func (s *chunkedHeaderSent) sendEkChunk() (*chunkedHeaderSent, chunk) {
	c := s.sendingEk.nextChunk()
	return s, c
}

func (s *chunkedHeaderSent) recv(msg *v1Message) (v1Recv, error) {
	switch {
	case msg.epoch > s.epoch():
		return v1Recv{}, ErrEpochOutOfRange
	case msg.epoch < s.epoch():
		return v1Recv{state: &v1States{state: s}}, nil
	default:
		if msg.payload.kind == MessageTypeCt1 && msg.payload.chunk != nil {
			next, err := s.recvCt1Chunk(msg.epoch, msg.payload.chunk)
			if err != nil {
				return v1Recv{}, err
			}
			return v1Recv{state: &v1States{state: next}}, nil
		}
		return v1Recv{state: &v1States{state: s}}, nil
	}
}

func (s *chunkedHeaderSent) recvCt1Chunk(epoch uint64, c *chunk) (any, error) {
	s.receivingCt1.addChunk(c)
	decoded, err := s.receivingCt1.decodedMessage()
	if err != nil {
		return nil, err
	}
	if decoded == nil {
		return s, nil
	}
	uc := s.uc.recvCt1(epoch, decoded)
	return &chunkedCt1Received{uc: uc, sendingEk: s.sendingEk}, nil
}

func (s *chunkedCt1Received) epoch() uint64 { return s.uc.epoch }

func (s *chunkedCt1Received) sendEkChunk() (*chunkedCt1Received, chunk) {
	c := s.sendingEk.nextChunk()
	return s, c
}

func (s *chunkedCt1Received) recv(msg *v1Message) (v1Recv, error) {
	switch {
	case msg.epoch > s.epoch():
		return v1Recv{}, ErrEpochOutOfRange
	case msg.epoch < s.epoch():
		return v1Recv{state: &v1States{state: s}}, nil
	default:
		if msg.payload.kind == MessageTypeCt2 && msg.payload.chunk != nil {
			next, err := s.recvCt2Chunk(msg.epoch, msg.payload.chunk)
			if err != nil {
				return v1Recv{}, err
			}
			return v1Recv{state: &v1States{state: next}}, nil
		}
		return v1Recv{state: &v1States{state: s}}, nil
	}
}

func (s *chunkedCt1Received) recvCt2Chunk(epoch uint64, c *chunk) (*chunkedEkSentCt1Received, error) {
	dec, err := newPolyDecoder(mlkemCiphertext2Size + authenticatorMacSize)
	if err != nil {
		return nil, err
	}
	dec.addChunk(c)
	return &chunkedEkSentCt1Received{uc: s.uc, receivingCt2: dec}, nil
}

func (s *chunkedEkSentCt1Received) epoch() uint64 { return s.uc.epoch }

func (s *chunkedEkSentCt1Received) recv(msg *v1Message) (v1Recv, error) {
	switch {
	case msg.epoch > s.epoch():
		return v1Recv{}, ErrEpochOutOfRange
	case msg.epoch < s.epoch():
		return v1Recv{state: &v1States{state: s}}, nil
	default:
		if msg.payload.kind == MessageTypeCt2 && msg.payload.chunk != nil {
			next, key, err := s.recvCt2Chunk(msg.epoch, msg.payload.chunk)
			if err != nil {
				return v1Recv{}, err
			}
			return v1Recv{state: next, key: key}, nil
		}
		return v1Recv{state: &v1States{state: s}}, nil
	}
}

func (s *chunkedEkSentCt1Received) recvCt2Chunk(epoch uint64, c *chunk) (*v1States, *epochSecret, error) {
	s.receivingCt2.addChunk(c)
	decoded, err := s.receivingCt2.decodedMessage()
	if err != nil {
		return nil, nil, err
	}
	if decoded == nil {
		return &v1States{state: s}, nil, nil
	}
	if len(decoded) < mlkemCiphertext2Size+authenticatorMacSize {
		return nil, nil, ErrInvalidMessage
	}
	ct2 := decoded[:mlkemCiphertext2Size]
	mac := decoded[mlkemCiphertext2Size:]
	nextUc, key, err := s.uc.recvCt2(ct2, mac)
	if err != nil {
		return nil, nil, err
	}
	dec, err := newPolyDecoder(mlkemHeaderSize + authenticatorMacSize)
	if err != nil {
		return nil, nil, err
	}
	return &v1States{state: &chunkedNoHeaderReceived{uc: nextUc, receivingHdr: dec}}, key, nil
}

func (s *chunkedNoHeaderReceived) epoch() uint64 { return s.uc.epoch }

func (s *chunkedNoHeaderReceived) recv(msg *v1Message) (v1Recv, error) {
	switch {
	case msg.epoch > s.epoch():
		return v1Recv{}, ErrEpochOutOfRange
	case msg.epoch < s.epoch():
		return v1Recv{state: &v1States{state: s}}, nil
	default:
		if msg.payload.kind == MessageTypeHdr && msg.payload.chunk != nil {
			next, err := s.recvHdrChunk(msg.epoch, msg.payload.chunk)
			if err != nil {
				return v1Recv{}, err
			}
			return v1Recv{state: &v1States{state: next}}, nil
		}
		return v1Recv{state: &v1States{state: s}}, nil
	}
}

func (s *chunkedNoHeaderReceived) recvHdrChunk(epoch uint64, c *chunk) (any, error) {
	s.receivingHdr.addChunk(c)
	decoded, err := s.receivingHdr.decodedMessage()
	if err != nil {
		return nil, err
	}
	if decoded == nil {
		return s, nil
	}
	if len(decoded) < mlkemHeaderSize+authenticatorMacSize {
		return nil, ErrInvalidMessage
	}
	hdr := decoded[:mlkemHeaderSize]
	mac := decoded[mlkemHeaderSize:]
	uc, err := s.uc.recvHeader(epoch, hdr, mac)
	if err != nil {
		return nil, err
	}
	dec, err := newPolyDecoder(mlkemEncapsulationKeySize)
	if err != nil {
		return nil, err
	}
	return &chunkedHeaderReceived{uc: uc, receivingEk: dec}, nil
}

func (s *chunkedHeaderReceived) epoch() uint64 { return s.uc.epoch }

func (s *chunkedHeaderReceived) sendCt1Chunk() (*chunkedCt1Sampled, chunk, *epochSecret, error) {
	uc, ct1, key, err := s.uc.sendCt1()
	if err != nil {
		return nil, chunk{}, nil, err
	}
	enc, err := newPolyEncoder(ct1)
	if err != nil {
		return nil, chunk{}, nil, err
	}
	c := enc.nextChunk()
	return &chunkedCt1Sampled{uc: uc, sendingCt1: enc, receivingEk: s.receivingEk}, c, key, nil
}

func (s *chunkedHeaderReceived) recv(msg *v1Message) (v1Recv, error) {
	switch {
	case msg.epoch > s.epoch():
		return v1Recv{}, ErrEpochOutOfRange
	case msg.epoch < s.epoch():
		return v1Recv{state: &v1States{state: s}}, nil
	default:
		return v1Recv{state: &v1States{state: s}}, nil
	}
}

func (s *chunkedCt1Sampled) epoch() uint64 { return s.uc.epoch }

func (s *chunkedCt1Sampled) sendCt1Chunk() (*chunkedCt1Sampled, chunk) {
	c := s.sendingCt1.nextChunk()
	return s, c
}

func (s *chunkedCt1Sampled) recv(msg *v1Message) (v1Recv, error) {
	switch {
	case msg.epoch > s.epoch():
		return v1Recv{}, ErrEpochOutOfRange
	case msg.epoch < s.epoch():
		return v1Recv{state: &v1States{state: s}}, nil
	default:
		chunk := msg.payload.chunk
		ack := msg.payload.kind == MessageTypeEkCt1Ack
		if msg.payload.kind != MessageTypeEk && msg.payload.kind != MessageTypeEkCt1Ack {
			chunk = nil
		}
		if chunk == nil {
			return v1Recv{state: &v1States{state: s}}, nil
		}
		next, err := s.recvEkChunk(msg.epoch, chunk, ack)
		if err != nil {
			return v1Recv{}, err
		}
		return v1Recv{state: &v1States{state: next}}, nil
	}
}

func (s *chunkedCt1Sampled) recvEkChunk(epoch uint64, c *chunk, ct1Ack bool) (any, error) {
	s.receivingEk.addChunk(c)
	decoded, err := s.receivingEk.decodedMessage()
	if err != nil {
		return nil, err
	}
	if decoded == nil {
		if ct1Ack {
			return &chunkedCt1Acknowledged{uc: s.uc, receivingEk: s.receivingEk}, nil
		}
		return s, nil
	}
	uc, err := s.uc.recvEk(epoch, decoded)
	if err != nil {
		return nil, err
	}
	if ct1Ack {
		ct2State, ct2, mac, err := uc.sendCt2()
		if err != nil {
			return nil, err
		}
		enc, err := newPolyEncoder(append(ct2, mac...))
		if err != nil {
			return nil, err
		}
		return &chunkedCt2Sampled{uc: ct2State, sendingCt2: enc}, nil
	}
	return &chunkedEkReceivedCt1Sampled{uc: uc, sendingCt1: s.sendingCt1}, nil
}

func (s *chunkedEkReceivedCt1Sampled) epoch() uint64 { return s.uc.epoch }

func (s *chunkedEkReceivedCt1Sampled) sendCt1Chunk() (*chunkedEkReceivedCt1Sampled, chunk) {
	c := s.sendingCt1.nextChunk()
	return s, c
}

func (s *chunkedEkReceivedCt1Sampled) recv(msg *v1Message) (v1Recv, error) {
	switch {
	case msg.epoch > s.epoch():
		return v1Recv{}, ErrEpochOutOfRange
	case msg.epoch < s.epoch():
		return v1Recv{state: &v1States{state: s}}, nil
	default:
		if msg.payload.kind == MessageTypeCt1Ack || msg.payload.kind == MessageTypeEkCt1Ack {
			next, err := s.recvCt1Ack(msg.epoch)
			if err != nil {
				return v1Recv{}, err
			}
			return v1Recv{state: &v1States{state: next}}, nil
		}
		return v1Recv{state: &v1States{state: s}}, nil
	}
}

func (s *chunkedEkReceivedCt1Sampled) recvCt1Ack(epoch uint64) (*chunkedCt2Sampled, error) {
	ct2State, ct2, mac, err := s.uc.sendCt2()
	if err != nil {
		return nil, err
	}
	enc, err := newPolyEncoder(append(ct2, mac...))
	if err != nil {
		return nil, err
	}
	return &chunkedCt2Sampled{uc: ct2State, sendingCt2: enc}, nil
}

func (s *chunkedCt1Acknowledged) epoch() uint64 { return s.uc.epoch }

func (s *chunkedCt1Acknowledged) recv(msg *v1Message) (v1Recv, error) {
	switch {
	case msg.epoch > s.epoch():
		return v1Recv{}, ErrEpochOutOfRange
	case msg.epoch < s.epoch():
		return v1Recv{state: &v1States{state: s}}, nil
	default:
		if msg.payload.kind == MessageTypeEk || msg.payload.kind == MessageTypeEkCt1Ack {
			if msg.payload.chunk == nil {
				return v1Recv{state: &v1States{state: s}}, nil
			}
			next, err := s.recvEkChunk(msg.epoch, msg.payload.chunk)
			if err != nil {
				return v1Recv{}, err
			}
			return v1Recv{state: &v1States{state: next}}, nil
		}
		return v1Recv{state: &v1States{state: s}}, nil
	}
}

func (s *chunkedCt1Acknowledged) recvEkChunk(epoch uint64, c *chunk) (any, error) {
	s.receivingEk.addChunk(c)
	decoded, err := s.receivingEk.decodedMessage()
	if err != nil {
		return nil, err
	}
	if decoded == nil {
		return s, nil
	}
	uc, err := s.uc.recvEk(epoch, decoded)
	if err != nil {
		return nil, err
	}
	ct2State, ct2, mac, err := uc.sendCt2()
	if err != nil {
		return nil, err
	}
	enc, err := newPolyEncoder(append(ct2, mac...))
	if err != nil {
		return nil, err
	}
	return &chunkedCt2Sampled{uc: ct2State, sendingCt2: enc}, nil
}

func (s *chunkedCt2Sampled) epoch() uint64 { return s.uc.epoch }

func (s *chunkedCt2Sampled) sendCt2Chunk() (*chunkedCt2Sampled, chunk) {
	c := s.sendingCt2.nextChunk()
	return s, c
}

func (s *chunkedCt2Sampled) recv(msg *v1Message) (v1Recv, error) {
	switch {
	case msg.epoch > s.epoch():
		if msg.epoch == s.epoch()+1 {
			next, err := s.recvNextEpoch(msg.epoch)
			if err != nil {
				return v1Recv{}, err
			}
			return v1Recv{state: &v1States{state: next}}, nil
		}
		return v1Recv{}, ErrEpochOutOfRange
	case msg.epoch < s.epoch():
		return v1Recv{state: &v1States{state: s}}, nil
	default:
		return v1Recv{state: &v1States{state: s}}, nil
	}
}

func (s *chunkedCt2Sampled) recvNextEpoch(epoch uint64) (*chunkedKeysUnsampled, error) {
	uc, err := s.uc.recvNextEpoch(epoch)
	if err != nil {
		return nil, err
	}
	return &chunkedKeysUnsampled{uc: uc}, nil
}
