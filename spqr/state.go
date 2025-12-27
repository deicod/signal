package spqr

import "fmt"

const (
	stateSerializeVersionV1 = 1
	stateSerializeVersionV2 = 2
)

type versionNegotiation struct {
	authKey     []byte
	direction   Direction
	minVersion  Version
	chainParams ChainParams
}

// State tracks SPQR chain and handshake state for deriving message-key salts.
type State struct {
	version     Version
	v1          *v1States
	chain       *Chain
	negotiation *versionNegotiation
}

// NewState initializes a new SPQR state from the auth key.
func NewState(authKey []byte, dir Direction, params ChainParams) (*State, error) {
	return NewStateWithMinVersion(authKey, dir, params, VersionDisabled)
}

// NewStateWithMinVersion initializes a new SPQR state with the provided minimum version.
func NewStateWithMinVersion(authKey []byte, dir Direction, params ChainParams, minVersion Version) (*State, error) {
	if len(authKey) == 0 {
		return nil, fmt.Errorf("spqr: auth key required")
	}
	if minVersion > VersionV1 {
		return nil, ErrUnsupportedVersion
	}
	v1, err := initV1StateForDirection(dir, authKey)
	if err != nil {
		return nil, err
	}
	return &State{
		version: VersionV1,
		v1:      v1,
		negotiation: &versionNegotiation{
			authKey:     append([]byte(nil), authKey...),
			direction:   dir,
			minVersion:  minVersion,
			chainParams: params,
		},
	}, nil
}

// Send advances the local SPQR state and returns the next pq_ratchet message and salt.
func (s *State) Send() ([]byte, []byte, error) {
	if s == nil {
		return nil, nil, ErrChainNotAvailable
	}
	if s.version == VersionDisabled || s.v1 == nil {
		return nil, nil, nil
	}

	send, err := s.v1.send()
	if err != nil {
		return nil, nil, err
	}

	chain, err := s.chainForSend()
	if err != nil {
		return nil, nil, err
	}

	var msgKey []byte
	idx := uint32(0)
	if chain != nil {
		if send.key != nil {
			if err := chain.AddEpoch(send.key.epoch, send.key.secret); err != nil {
				return nil, nil, err
			}
		}
		if send.msg.epoch == 0 {
			return nil, nil, ErrEpochOutOfRange
		}
		idx, msgKey, err = chain.SendKey(send.msg.epoch - 1)
		if err != nil {
			return nil, nil, err
		}
	} else if send.key != nil {
		return nil, nil, ErrChainNotAvailable
	}

	msg := send.msg.serialize(idx)
	s.v1 = send.state
	if chain != nil {
		s.chain = chain
	}
	if len(msg) == 0 {
		msg = nil
	}
	if len(msgKey) == 0 {
		msgKey = nil
	}
	return msg, msgKey, nil
}

// Receive processes a pq_ratchet message and returns the derived message-key salt.
func (s *State) Receive(message []byte) ([]byte, error) {
	if s == nil {
		return nil, ErrChainNotAvailable
	}
	if s.v1 == nil {
		return s.receiveLegacy(message)
	}

	version, ok := msgVersion(message)
	if !ok {
		return nil, nil
	}
	if s.version == VersionDisabled {
		return nil, nil
	}
	if version < s.version {
		if s.negotiation == nil {
			return nil, ErrVersionMismatch
		}
		if version < s.negotiation.minVersion {
			return nil, ErrMinimumVersion
		}
		if version == VersionDisabled {
			s.disable()
			return nil, nil
		}
	}
	if version == VersionDisabled {
		return nil, nil
	}

	msg, idx, _, err := deserializeV1Message(message)
	if err != nil {
		return nil, err
	}
	recv, err := s.v1.recv(&msg)
	if err != nil {
		return nil, err
	}
	if msg.epoch == 0 {
		return nil, ErrEpochOutOfRange
	}
	chain, err := s.chainForRecv()
	if err != nil {
		return nil, err
	}
	if recv.key != nil {
		if err := chain.AddEpoch(recv.key.epoch, recv.key.secret); err != nil {
			return nil, err
		}
	}
	msgKeyEpoch := msg.epoch - 1
	var msgKey []byte
	if msgKeyEpoch != 0 || idx != 0 {
		msgKey, err = chain.RecvKey(msgKeyEpoch, idx)
		if err != nil {
			return nil, err
		}
	}

	s.v1 = recv.state
	s.chain = chain
	s.negotiation = nil
	if len(msgKey) == 0 {
		msgKey = nil
	}
	return msgKey, nil
}

// Serialize encodes the SPQR state for persistence.
func (s *State) Serialize() ([]byte, error) {
	if s == nil {
		return nil, nil
	}
	if s.version == VersionDisabled {
		return nil, nil
	}
	if s.v1 == nil {
		return serializeLegacyState(s)
	}
	v1Bytes, err := serializeV1States(s.v1)
	if err != nil {
		return nil, err
	}
	flags := byte(0)
	if s.negotiation != nil {
		flags |= 0x01
	}
	if s.chain != nil {
		flags |= 0x02
	}
	out := make([]byte, 0, 32+len(v1Bytes))
	out = append(out, stateSerializeVersionV2, byte(s.version), flags)
	if s.negotiation != nil {
		out = append(out, byte(s.negotiation.minVersion), byte(s.negotiation.direction))
		out = appendUint32(out, s.negotiation.chainParams.MaxJump)
		out = appendUint32(out, s.negotiation.chainParams.MaxOOO)
		out = appendBytes(out, s.negotiation.authKey)
	}
	out = appendUint32(out, uint32(len(v1Bytes)))
	out = append(out, v1Bytes...)
	if s.chain != nil {
		chainBytes, err := serializeChain(s.chain)
		if err != nil {
			return nil, err
		}
		out = appendUint32(out, uint32(len(chainBytes)))
		out = append(out, chainBytes...)
	}
	return out, nil
}

// DeserializeState decodes a persisted SPQR state.
func DeserializeState(data []byte) (*State, error) {
	if len(data) == 0 {
		return nil, nil
	}
	switch data[0] {
	case stateSerializeVersionV1:
		pos := 1
		if pos >= len(data) {
			return nil, ErrStateDecode
		}
		pos++
		if pos+4 > len(data) {
			return nil, ErrStateDecode
		}
		chainLen := int(readUint32(data[pos : pos+4]))
		pos += 4
		if chainLen < 0 || pos+chainLen > len(data) {
			return nil, ErrStateDecode
		}
		chain, err := deserializeChain(data[pos : pos+chainLen])
		if err != nil {
			return nil, err
		}
		pos += chainLen
		if pos != len(data) {
			return nil, ErrStateDecode
		}
		return &State{version: VersionV1, chain: chain}, nil
	case stateSerializeVersionV2:
		pos := 1
		if pos+2 > len(data) {
			return nil, ErrStateDecode
		}
		version := Version(data[pos])
		pos++
		flags := data[pos]
		pos++
		if version != VersionV1 {
			return nil, ErrStateDecode
		}
		var negotiation *versionNegotiation
		if flags&0x01 != 0 {
			if pos+2+4+4 > len(data) {
				return nil, ErrStateDecode
			}
			minVersion := Version(data[pos])
			pos++
			direction := Direction(data[pos])
			pos++
			if minVersion > VersionV1 {
				return nil, ErrStateDecode
			}
			if direction != DirectionA2B && direction != DirectionB2A {
				return nil, ErrStateDecode
			}
			maxJump := readUint32(data[pos : pos+4])
			pos += 4
			maxOOO := readUint32(data[pos : pos+4])
			pos += 4
			authKey, err := readBytes(data, &pos)
			if err != nil {
				return nil, err
			}
			if len(authKey) == 0 {
				return nil, ErrStateDecode
			}
			negotiation = &versionNegotiation{
				authKey:     authKey,
				direction:   direction,
				minVersion:  minVersion,
				chainParams: ChainParams{MaxJump: maxJump, MaxOOO: maxOOO},
			}
		}
		if pos+4 > len(data) {
			return nil, ErrStateDecode
		}
		v1Len := int(readUint32(data[pos : pos+4]))
		pos += 4
		if v1Len < 0 || pos+v1Len > len(data) {
			return nil, ErrStateDecode
		}
		v1, err := deserializeV1States(data[pos : pos+v1Len])
		if err != nil {
			return nil, err
		}
		pos += v1Len
		var chain *Chain
		if flags&0x02 != 0 {
			if pos+4 > len(data) {
				return nil, ErrStateDecode
			}
			chainLen := int(readUint32(data[pos : pos+4]))
			pos += 4
			if chainLen < 0 || pos+chainLen > len(data) {
				return nil, ErrStateDecode
			}
			chain, err = deserializeChain(data[pos : pos+chainLen])
			if err != nil {
				return nil, err
			}
			pos += chainLen
		}
		if pos != len(data) {
			return nil, ErrStateDecode
		}
		return &State{
			version:     version,
			v1:          v1,
			chain:       chain,
			negotiation: negotiation,
		}, nil
	default:
		return nil, ErrStateDecode
	}
}

// Clone returns a copy of the state.
func (s *State) Clone() *State {
	if s == nil {
		return nil
	}
	clone := &State{version: s.version}
	if s.v1 != nil {
		v1Bytes, err := serializeV1States(s.v1)
		if err != nil {
			return nil
		}
		v1, err := deserializeV1States(v1Bytes)
		if err != nil {
			return nil
		}
		clone.v1 = v1
	}
	if s.chain != nil {
		chainBytes, err := serializeChain(s.chain)
		if err != nil {
			return nil
		}
		chain, err := deserializeChain(chainBytes)
		if err != nil {
			return nil
		}
		clone.chain = chain
	}
	if s.negotiation != nil {
		clone.negotiation = cloneNegotiation(s.negotiation)
	}
	return clone
}

func (s *State) receiveLegacy(message []byte) ([]byte, error) {
	if s.chain == nil {
		return nil, ErrChainNotAvailable
	}
	if len(message) == 0 {
		return nil, nil
	}
	msg, err := ParseMessage(message)
	if err != nil {
		if err == ErrUnsupportedVersion {
			return nil, nil
		}
		return nil, err
	}
	if msg.Version != VersionV1 {
		return nil, nil
	}
	if msg.Epoch == 0 {
		return nil, ErrEpochOutOfRange
	}
	msgKeyEpoch := msg.Epoch - 1
	if msgKeyEpoch == 0 && msg.Index == 0 {
		return nil, nil
	}
	return s.chain.RecvKey(msgKeyEpoch, msg.Index)
}

func serializeLegacyState(s *State) ([]byte, error) {
	chainBytes, err := serializeChain(s.chain)
	if err != nil {
		return nil, err
	}
	dir := DirectionA2B
	if s.chain != nil {
		dir = s.chain.dir
	} else if s.negotiation != nil {
		dir = s.negotiation.direction
	}
	out := make([]byte, 0, 2+4+len(chainBytes))
	out = append(out, stateSerializeVersionV1)
	out = append(out, byte(dir))
	out = appendUint32(out, uint32(len(chainBytes)))
	out = append(out, chainBytes...)
	return out, nil
}

func (s *State) disable() {
	s.version = VersionDisabled
	s.v1 = nil
	s.chain = nil
	s.negotiation = nil
}

func msgVersion(message []byte) (Version, bool) {
	if len(message) == 0 {
		return VersionDisabled, true
	}
	switch Version(message[0]) {
	case VersionDisabled, VersionV1:
		return Version(message[0]), true
	default:
		return 0, false
	}
}

func initV1StateForDirection(dir Direction, authKey []byte) (*v1States, error) {
	switch dir {
	case DirectionA2B:
		return initV1StateA(authKey)
	case DirectionB2A:
		return initV1StateB(authKey)
	default:
		return initV1StateA(authKey)
	}
}

func (s *State) chainForSend() (*Chain, error) {
	if s.chain != nil {
		return s.chain, nil
	}
	if s.negotiation == nil {
		return nil, ErrChainNotAvailable
	}
	if s.negotiation.minVersion <= VersionDisabled {
		return nil, nil
	}
	chain, err := chainFromNegotiation(s.negotiation)
	if err != nil {
		return nil, err
	}
	s.chain = chain
	return chain, nil
}

func (s *State) chainForRecv() (*Chain, error) {
	if s.chain != nil {
		return s.chain, nil
	}
	if s.negotiation == nil {
		return nil, ErrChainNotAvailable
	}
	chain, err := chainFromNegotiation(s.negotiation)
	if err != nil {
		return nil, err
	}
	return chain, nil
}

func chainFromNegotiation(vn *versionNegotiation) (*Chain, error) {
	if vn == nil {
		return nil, ErrChainNotAvailable
	}
	return NewChain(vn.authKey, vn.direction, vn.chainParams)
}

func cloneNegotiation(vn *versionNegotiation) *versionNegotiation {
	if vn == nil {
		return nil
	}
	return &versionNegotiation{
		authKey:     append([]byte(nil), vn.authKey...),
		direction:   vn.direction,
		minVersion:  vn.minVersion,
		chainParams: vn.chainParams,
	}
}
