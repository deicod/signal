package spqr

const (
	v1StateKeysUnsampled uint8 = iota + 1
	v1StateKeysSampled
	v1StateHeaderSent
	v1StateCt1Received
	v1StateEkSentCt1Received
	v1StateNoHeaderReceived
	v1StateHeaderReceived
	v1StateCt1Sampled
	v1StateEkReceivedCt1Sampled
	v1StateCt1Acknowledged
	v1StateCt2Sampled
)

func serializeV1States(s *v1States) ([]byte, error) {
	if s == nil || s.state == nil {
		return nil, ErrStateDecode
	}
	out := make([]byte, 0, 128)
	switch st := s.state.(type) {
	case *chunkedKeysUnsampled:
		out = append(out, v1StateKeysUnsampled)
		uc, err := serializeUnchunkedKeysUnsampled(st.uc)
		if err != nil {
			return nil, err
		}
		out = appendBytes(out, uc)
	case *chunkedKeysSampled:
		out = append(out, v1StateKeysSampled)
		uc, err := serializeUnchunkedHeaderSent(st.uc)
		if err != nil {
			return nil, err
		}
		out = appendBytes(out, uc)
		out = appendBytes(out, st.sendingHdr.serialize())
	case *chunkedHeaderSent:
		out = append(out, v1StateHeaderSent)
		uc, err := serializeUnchunkedEkSent(st.uc)
		if err != nil {
			return nil, err
		}
		out = appendBytes(out, uc)
		out = appendBytes(out, st.sendingEk.serialize())
		out = appendBytes(out, st.receivingCt1.serialize())
	case *chunkedCt1Received:
		out = append(out, v1StateCt1Received)
		uc, err := serializeUnchunkedEkSentCt1Received(st.uc)
		if err != nil {
			return nil, err
		}
		out = appendBytes(out, uc)
		out = appendBytes(out, st.sendingEk.serialize())
	case *chunkedEkSentCt1Received:
		out = append(out, v1StateEkSentCt1Received)
		uc, err := serializeUnchunkedEkSentCt1Received(st.uc)
		if err != nil {
			return nil, err
		}
		out = appendBytes(out, uc)
		out = appendBytes(out, st.receivingCt2.serialize())
	case *chunkedNoHeaderReceived:
		out = append(out, v1StateNoHeaderReceived)
		uc, err := serializeUnchunkedNoHeaderReceived(st.uc)
		if err != nil {
			return nil, err
		}
		out = appendBytes(out, uc)
		out = appendBytes(out, st.receivingHdr.serialize())
	case *chunkedHeaderReceived:
		out = append(out, v1StateHeaderReceived)
		uc, err := serializeUnchunkedHeaderReceived(st.uc)
		if err != nil {
			return nil, err
		}
		out = appendBytes(out, uc)
		out = appendBytes(out, st.receivingEk.serialize())
	case *chunkedCt1Sampled:
		out = append(out, v1StateCt1Sampled)
		uc, err := serializeUnchunkedCt1Sent(st.uc)
		if err != nil {
			return nil, err
		}
		out = appendBytes(out, uc)
		out = appendBytes(out, st.sendingCt1.serialize())
		out = appendBytes(out, st.receivingEk.serialize())
	case *chunkedEkReceivedCt1Sampled:
		out = append(out, v1StateEkReceivedCt1Sampled)
		uc, err := serializeUnchunkedCt1SentEkReceived(st.uc)
		if err != nil {
			return nil, err
		}
		out = appendBytes(out, uc)
		out = appendBytes(out, st.sendingCt1.serialize())
	case *chunkedCt1Acknowledged:
		out = append(out, v1StateCt1Acknowledged)
		uc, err := serializeUnchunkedCt1Sent(st.uc)
		if err != nil {
			return nil, err
		}
		out = appendBytes(out, uc)
		out = appendBytes(out, st.receivingEk.serialize())
	case *chunkedCt2Sampled:
		out = append(out, v1StateCt2Sampled)
		uc, err := serializeUnchunkedCt2Sent(st.uc)
		if err != nil {
			return nil, err
		}
		out = appendBytes(out, uc)
		out = appendBytes(out, st.sendingCt2.serialize())
	default:
		return nil, ErrStateDecode
	}
	return out, nil
}

func deserializeV1States(data []byte) (*v1States, error) {
	if len(data) == 0 {
		return nil, ErrStateDecode
	}
	pos := 1
	switch data[0] {
	case v1StateKeysUnsampled:
		ucBytes, err := readBytes(data, &pos)
		if err != nil {
			return nil, err
		}
		uc, err := deserializeUnchunkedKeysUnsampled(ucBytes)
		if err != nil {
			return nil, err
		}
		if pos != len(data) {
			return nil, ErrStateDecode
		}
		return &v1States{state: &chunkedKeysUnsampled{uc: uc}}, nil
	case v1StateKeysSampled:
		ucBytes, err := readBytes(data, &pos)
		if err != nil {
			return nil, err
		}
		encBytes, err := readBytes(data, &pos)
		if err != nil {
			return nil, err
		}
		uc, err := deserializeUnchunkedHeaderSent(ucBytes)
		if err != nil {
			return nil, err
		}
		enc, err := decodePolyEncoderWithSize(encBytes, mlkemHeaderSize+authenticatorMacSize)
		if err != nil {
			return nil, err
		}
		if pos != len(data) {
			return nil, ErrStateDecode
		}
		return &v1States{state: &chunkedKeysSampled{uc: uc, sendingHdr: enc}}, nil
	case v1StateHeaderSent:
		ucBytes, err := readBytes(data, &pos)
		if err != nil {
			return nil, err
		}
		encBytes, err := readBytes(data, &pos)
		if err != nil {
			return nil, err
		}
		decBytes, err := readBytes(data, &pos)
		if err != nil {
			return nil, err
		}
		uc, err := deserializeUnchunkedEkSent(ucBytes)
		if err != nil {
			return nil, err
		}
		enc, err := decodePolyEncoderWithSize(encBytes, mlkemEncapsulationKeySize)
		if err != nil {
			return nil, err
		}
		dec, err := decodePolyDecoderWithSize(decBytes, mlkemCiphertext1Size)
		if err != nil {
			return nil, err
		}
		if pos != len(data) {
			return nil, ErrStateDecode
		}
		return &v1States{state: &chunkedHeaderSent{uc: uc, sendingEk: enc, receivingCt1: dec}}, nil
	case v1StateCt1Received:
		ucBytes, err := readBytes(data, &pos)
		if err != nil {
			return nil, err
		}
		encBytes, err := readBytes(data, &pos)
		if err != nil {
			return nil, err
		}
		uc, err := deserializeUnchunkedEkSentCt1Received(ucBytes)
		if err != nil {
			return nil, err
		}
		enc, err := decodePolyEncoderWithSize(encBytes, mlkemEncapsulationKeySize)
		if err != nil {
			return nil, err
		}
		if pos != len(data) {
			return nil, ErrStateDecode
		}
		return &v1States{state: &chunkedCt1Received{uc: uc, sendingEk: enc}}, nil
	case v1StateEkSentCt1Received:
		ucBytes, err := readBytes(data, &pos)
		if err != nil {
			return nil, err
		}
		decBytes, err := readBytes(data, &pos)
		if err != nil {
			return nil, err
		}
		uc, err := deserializeUnchunkedEkSentCt1Received(ucBytes)
		if err != nil {
			return nil, err
		}
		dec, err := decodePolyDecoderWithSize(decBytes, mlkemCiphertext2Size+authenticatorMacSize)
		if err != nil {
			return nil, err
		}
		if pos != len(data) {
			return nil, ErrStateDecode
		}
		return &v1States{state: &chunkedEkSentCt1Received{uc: uc, receivingCt2: dec}}, nil
	case v1StateNoHeaderReceived:
		ucBytes, err := readBytes(data, &pos)
		if err != nil {
			return nil, err
		}
		decBytes, err := readBytes(data, &pos)
		if err != nil {
			return nil, err
		}
		uc, err := deserializeUnchunkedNoHeaderReceived(ucBytes)
		if err != nil {
			return nil, err
		}
		dec, err := decodePolyDecoderWithSize(decBytes, mlkemHeaderSize+authenticatorMacSize)
		if err != nil {
			return nil, err
		}
		if pos != len(data) {
			return nil, ErrStateDecode
		}
		return &v1States{state: &chunkedNoHeaderReceived{uc: uc, receivingHdr: dec}}, nil
	case v1StateHeaderReceived:
		ucBytes, err := readBytes(data, &pos)
		if err != nil {
			return nil, err
		}
		decBytes, err := readBytes(data, &pos)
		if err != nil {
			return nil, err
		}
		uc, err := deserializeUnchunkedHeaderReceived(ucBytes)
		if err != nil {
			return nil, err
		}
		dec, err := decodePolyDecoderWithSize(decBytes, mlkemEncapsulationKeySize)
		if err != nil {
			return nil, err
		}
		if pos != len(data) {
			return nil, ErrStateDecode
		}
		return &v1States{state: &chunkedHeaderReceived{uc: uc, receivingEk: dec}}, nil
	case v1StateCt1Sampled:
		ucBytes, err := readBytes(data, &pos)
		if err != nil {
			return nil, err
		}
		encBytes, err := readBytes(data, &pos)
		if err != nil {
			return nil, err
		}
		decBytes, err := readBytes(data, &pos)
		if err != nil {
			return nil, err
		}
		uc, err := deserializeUnchunkedCt1Sent(ucBytes)
		if err != nil {
			return nil, err
		}
		enc, err := decodePolyEncoderWithSize(encBytes, mlkemCiphertext1Size)
		if err != nil {
			return nil, err
		}
		dec, err := decodePolyDecoderWithSize(decBytes, mlkemEncapsulationKeySize)
		if err != nil {
			return nil, err
		}
		if pos != len(data) {
			return nil, ErrStateDecode
		}
		return &v1States{state: &chunkedCt1Sampled{uc: uc, sendingCt1: enc, receivingEk: dec}}, nil
	case v1StateEkReceivedCt1Sampled:
		ucBytes, err := readBytes(data, &pos)
		if err != nil {
			return nil, err
		}
		encBytes, err := readBytes(data, &pos)
		if err != nil {
			return nil, err
		}
		uc, err := deserializeUnchunkedCt1SentEkReceived(ucBytes)
		if err != nil {
			return nil, err
		}
		enc, err := decodePolyEncoderWithSize(encBytes, mlkemCiphertext1Size)
		if err != nil {
			return nil, err
		}
		if pos != len(data) {
			return nil, ErrStateDecode
		}
		return &v1States{state: &chunkedEkReceivedCt1Sampled{uc: uc, sendingCt1: enc}}, nil
	case v1StateCt1Acknowledged:
		ucBytes, err := readBytes(data, &pos)
		if err != nil {
			return nil, err
		}
		decBytes, err := readBytes(data, &pos)
		if err != nil {
			return nil, err
		}
		uc, err := deserializeUnchunkedCt1Sent(ucBytes)
		if err != nil {
			return nil, err
		}
		dec, err := decodePolyDecoderWithSize(decBytes, mlkemEncapsulationKeySize)
		if err != nil {
			return nil, err
		}
		if pos != len(data) {
			return nil, ErrStateDecode
		}
		return &v1States{state: &chunkedCt1Acknowledged{uc: uc, receivingEk: dec}}, nil
	case v1StateCt2Sampled:
		ucBytes, err := readBytes(data, &pos)
		if err != nil {
			return nil, err
		}
		encBytes, err := readBytes(data, &pos)
		if err != nil {
			return nil, err
		}
		uc, err := deserializeUnchunkedCt2Sent(ucBytes)
		if err != nil {
			return nil, err
		}
		enc, err := decodePolyEncoderWithSize(encBytes, mlkemCiphertext2Size+authenticatorMacSize)
		if err != nil {
			return nil, err
		}
		if pos != len(data) {
			return nil, ErrStateDecode
		}
		return &v1States{state: &chunkedCt2Sampled{uc: uc, sendingCt2: enc}}, nil
	default:
		return nil, ErrStateDecode
	}
}

func serializeUnchunkedKeysUnsampled(s *unchunkedKeysUnsampled) ([]byte, error) {
	if s == nil || s.auth == nil {
		return nil, ErrStateDecode
	}
	out := make([]byte, 0, 80)
	out = appendUint64(out, s.epoch)
	out, err := appendAuthenticator(out, s.auth)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func deserializeUnchunkedKeysUnsampled(data []byte) (*unchunkedKeysUnsampled, error) {
	pos := 0
	if pos+8 > len(data) {
		return nil, ErrStateDecode
	}
	epoch := readUint64(data[pos : pos+8])
	pos += 8
	auth, err := readAuthenticator(data, &pos)
	if err != nil {
		return nil, err
	}
	if pos != len(data) {
		return nil, ErrStateDecode
	}
	return &unchunkedKeysUnsampled{epoch: epoch, auth: auth}, nil
}

func serializeUnchunkedHeaderSent(s *unchunkedHeaderSent) ([]byte, error) {
	if s == nil || s.auth == nil {
		return nil, ErrStateDecode
	}
	out := make([]byte, 0, 1600)
	out = appendUint64(out, s.epoch)
	out, err := appendAuthenticator(out, s.auth)
	if err != nil {
		return nil, err
	}
	out = appendBytes(out, s.ek)
	out = appendBytes(out, s.dk)
	return out, nil
}

func deserializeUnchunkedHeaderSent(data []byte) (*unchunkedHeaderSent, error) {
	pos := 0
	if pos+8 > len(data) {
		return nil, ErrStateDecode
	}
	epoch := readUint64(data[pos : pos+8])
	pos += 8
	auth, err := readAuthenticator(data, &pos)
	if err != nil {
		return nil, err
	}
	ek, err := readBytes(data, &pos)
	if err != nil {
		return nil, err
	}
	dk, err := readBytes(data, &pos)
	if err != nil {
		return nil, err
	}
	if len(ek) != mlkemEncapsulationKeySize || len(dk) != mlkemDecapsulationKeySize {
		return nil, ErrStateDecode
	}
	if pos != len(data) {
		return nil, ErrStateDecode
	}
	return &unchunkedHeaderSent{epoch: epoch, auth: auth, ek: ek, dk: dk}, nil
}

func serializeUnchunkedEkSent(s *unchunkedEkSent) ([]byte, error) {
	if s == nil || s.auth == nil {
		return nil, ErrStateDecode
	}
	out := make([]byte, 0, 600)
	out = appendUint64(out, s.epoch)
	out, err := appendAuthenticator(out, s.auth)
	if err != nil {
		return nil, err
	}
	out = appendBytes(out, s.dk)
	return out, nil
}

func deserializeUnchunkedEkSent(data []byte) (*unchunkedEkSent, error) {
	pos := 0
	if pos+8 > len(data) {
		return nil, ErrStateDecode
	}
	epoch := readUint64(data[pos : pos+8])
	pos += 8
	auth, err := readAuthenticator(data, &pos)
	if err != nil {
		return nil, err
	}
	dk, err := readBytes(data, &pos)
	if err != nil {
		return nil, err
	}
	if len(dk) != mlkemDecapsulationKeySize {
		return nil, ErrStateDecode
	}
	if pos != len(data) {
		return nil, ErrStateDecode
	}
	return &unchunkedEkSent{epoch: epoch, auth: auth, dk: dk}, nil
}

func serializeUnchunkedEkSentCt1Received(s *unchunkedEkSentCt1Received) ([]byte, error) {
	if s == nil || s.auth == nil {
		return nil, ErrStateDecode
	}
	out := make([]byte, 0, 1800)
	out = appendUint64(out, s.epoch)
	out, err := appendAuthenticator(out, s.auth)
	if err != nil {
		return nil, err
	}
	out = appendBytes(out, s.dk)
	out = appendBytes(out, s.ct1)
	return out, nil
}

func deserializeUnchunkedEkSentCt1Received(data []byte) (*unchunkedEkSentCt1Received, error) {
	pos := 0
	if pos+8 > len(data) {
		return nil, ErrStateDecode
	}
	epoch := readUint64(data[pos : pos+8])
	pos += 8
	auth, err := readAuthenticator(data, &pos)
	if err != nil {
		return nil, err
	}
	dk, err := readBytes(data, &pos)
	if err != nil {
		return nil, err
	}
	ct1, err := readBytes(data, &pos)
	if err != nil {
		return nil, err
	}
	if len(dk) != mlkemDecapsulationKeySize || len(ct1) != mlkemCiphertext1Size {
		return nil, ErrStateDecode
	}
	if pos != len(data) {
		return nil, ErrStateDecode
	}
	return &unchunkedEkSentCt1Received{epoch: epoch, auth: auth, dk: dk, ct1: ct1}, nil
}

func serializeUnchunkedNoHeaderReceived(s *unchunkedNoHeaderReceived) ([]byte, error) {
	if s == nil || s.auth == nil {
		return nil, ErrStateDecode
	}
	out := make([]byte, 0, 80)
	out = appendUint64(out, s.epoch)
	out, err := appendAuthenticator(out, s.auth)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func deserializeUnchunkedNoHeaderReceived(data []byte) (*unchunkedNoHeaderReceived, error) {
	pos := 0
	if pos+8 > len(data) {
		return nil, ErrStateDecode
	}
	epoch := readUint64(data[pos : pos+8])
	pos += 8
	auth, err := readAuthenticator(data, &pos)
	if err != nil {
		return nil, err
	}
	if pos != len(data) {
		return nil, ErrStateDecode
	}
	return &unchunkedNoHeaderReceived{epoch: epoch, auth: auth}, nil
}

func serializeUnchunkedHeaderReceived(s *unchunkedHeaderReceived) ([]byte, error) {
	if s == nil || s.auth == nil {
		return nil, ErrStateDecode
	}
	out := make([]byte, 0, 120)
	out = appendUint64(out, s.epoch)
	out, err := appendAuthenticator(out, s.auth)
	if err != nil {
		return nil, err
	}
	out = appendBytes(out, s.hdr)
	return out, nil
}

func deserializeUnchunkedHeaderReceived(data []byte) (*unchunkedHeaderReceived, error) {
	pos := 0
	if pos+8 > len(data) {
		return nil, ErrStateDecode
	}
	epoch := readUint64(data[pos : pos+8])
	pos += 8
	auth, err := readAuthenticator(data, &pos)
	if err != nil {
		return nil, err
	}
	hdr, err := readBytes(data, &pos)
	if err != nil {
		return nil, err
	}
	if len(hdr) != mlkemHeaderSize {
		return nil, ErrStateDecode
	}
	if pos != len(data) {
		return nil, ErrStateDecode
	}
	return &unchunkedHeaderReceived{epoch: epoch, auth: auth, hdr: hdr}, nil
}

func serializeUnchunkedCt1Sent(s *unchunkedCt1Sent) ([]byte, error) {
	if s == nil || s.auth == nil {
		return nil, ErrStateDecode
	}
	out := make([]byte, 0, 1200)
	out = appendUint64(out, s.epoch)
	out, err := appendAuthenticator(out, s.auth)
	if err != nil {
		return nil, err
	}
	out = appendBytes(out, s.hdr)
	out = appendEncapsulationState(out, s.encaps)
	out = appendBytes(out, s.ct1)
	return out, nil
}

func deserializeUnchunkedCt1Sent(data []byte) (*unchunkedCt1Sent, error) {
	pos := 0
	if pos+8 > len(data) {
		return nil, ErrStateDecode
	}
	epoch := readUint64(data[pos : pos+8])
	pos += 8
	auth, err := readAuthenticator(data, &pos)
	if err != nil {
		return nil, err
	}
	hdr, err := readBytes(data, &pos)
	if err != nil {
		return nil, err
	}
	encaps, err := readEncapsulationState(data, &pos)
	if err != nil {
		return nil, err
	}
	ct1, err := readBytes(data, &pos)
	if err != nil {
		return nil, err
	}
	if len(hdr) != mlkemHeaderSize || len(ct1) != mlkemCiphertext1Size {
		return nil, ErrStateDecode
	}
	if pos != len(data) {
		return nil, ErrStateDecode
	}
	return &unchunkedCt1Sent{epoch: epoch, auth: auth, hdr: hdr, encaps: encaps, ct1: ct1}, nil
}

func serializeUnchunkedCt1SentEkReceived(s *unchunkedCt1SentEkReceived) ([]byte, error) {
	if s == nil || s.auth == nil {
		return nil, ErrStateDecode
	}
	out := make([]byte, 0, 2000)
	out = appendUint64(out, s.epoch)
	out, err := appendAuthenticator(out, s.auth)
	if err != nil {
		return nil, err
	}
	out = appendEncapsulationState(out, s.encaps)
	out = appendBytes(out, s.ek)
	out = appendBytes(out, s.ct1)
	return out, nil
}

func deserializeUnchunkedCt1SentEkReceived(data []byte) (*unchunkedCt1SentEkReceived, error) {
	pos := 0
	if pos+8 > len(data) {
		return nil, ErrStateDecode
	}
	epoch := readUint64(data[pos : pos+8])
	pos += 8
	auth, err := readAuthenticator(data, &pos)
	if err != nil {
		return nil, err
	}
	encaps, err := readEncapsulationState(data, &pos)
	if err != nil {
		return nil, err
	}
	ek, err := readBytes(data, &pos)
	if err != nil {
		return nil, err
	}
	ct1, err := readBytes(data, &pos)
	if err != nil {
		return nil, err
	}
	if len(ek) != mlkemEncapsulationKeySize || len(ct1) != mlkemCiphertext1Size {
		return nil, ErrStateDecode
	}
	if pos != len(data) {
		return nil, ErrStateDecode
	}
	return &unchunkedCt1SentEkReceived{epoch: epoch, auth: auth, encaps: encaps, ek: ek, ct1: ct1}, nil
}

func serializeUnchunkedCt2Sent(s *unchunkedCt2Sent) ([]byte, error) {
	if s == nil || s.auth == nil {
		return nil, ErrStateDecode
	}
	out := make([]byte, 0, 80)
	out = appendUint64(out, s.epoch)
	out, err := appendAuthenticator(out, s.auth)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func deserializeUnchunkedCt2Sent(data []byte) (*unchunkedCt2Sent, error) {
	pos := 0
	if pos+8 > len(data) {
		return nil, ErrStateDecode
	}
	epoch := readUint64(data[pos : pos+8])
	pos += 8
	auth, err := readAuthenticator(data, &pos)
	if err != nil {
		return nil, err
	}
	if pos != len(data) {
		return nil, ErrStateDecode
	}
	return &unchunkedCt2Sent{epoch: epoch, auth: auth}, nil
}

func appendAuthenticator(out []byte, a *authenticator) ([]byte, error) {
	if a == nil {
		return nil, ErrStateDecode
	}
	out = appendBytes(out, a.rootKey)
	out = appendBytes(out, a.macKey)
	return out, nil
}

func readAuthenticator(data []byte, pos *int) (*authenticator, error) {
	rootKey, err := readBytes(data, pos)
	if err != nil {
		return nil, err
	}
	macKey, err := readBytes(data, pos)
	if err != nil {
		return nil, err
	}
	if len(rootKey) != 32 || len(macKey) != 32 {
		return nil, ErrStateDecode
	}
	return &authenticator{
		rootKey: rootKey,
		macKey:  macKey,
	}, nil
}

func appendEncapsulationState(out []byte, state mlkemEncapsulationState) []byte {
	out = appendBytes(out, state.seed[:])
	out = appendBytes(out, state.rho[:])
	out = appendBytes(out, state.pkHash[:])
	return out
}

func readEncapsulationState(data []byte, pos *int) (mlkemEncapsulationState, error) {
	seed, err := readBytes(data, pos)
	if err != nil {
		return mlkemEncapsulationState{}, err
	}
	rho, err := readBytes(data, pos)
	if err != nil {
		return mlkemEncapsulationState{}, err
	}
	pkHash, err := readBytes(data, pos)
	if err != nil {
		return mlkemEncapsulationState{}, err
	}
	if len(seed) != 32 || len(rho) != 32 || len(pkHash) != 32 {
		return mlkemEncapsulationState{}, ErrStateDecode
	}
	var state mlkemEncapsulationState
	copy(state.seed[:], seed)
	copy(state.rho[:], rho)
	copy(state.pkHash[:], pkHash)
	return state, nil
}

func decodePolyEncoderWithSize(data []byte, size int) (*polyEncoder, error) {
	enc, err := decodePolyEncoder(data)
	if err != nil {
		return nil, err
	}
	if len(enc.msg) != size {
		return nil, ErrStateDecode
	}
	return enc, nil
}

func decodePolyDecoderWithSize(data []byte, size int) (*polyDecoder, error) {
	dec, err := decodePolyDecoder(data)
	if err != nil {
		return nil, err
	}
	if dec.ptsNeeded*2 != size {
		return nil, ErrStateDecode
	}
	return dec, nil
}
