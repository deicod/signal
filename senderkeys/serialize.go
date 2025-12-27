package senderkeys

import (
	"encoding/binary"
	"fmt"

	signalerrors "github.com/deicod/signal/errors"
)

var recordSerializeMagic = [4]byte{'S', 'I', 'G', 'K'}

const (
	recordSerializeVersion byte = 2
	recordMinSize               = 4 + 1 + 2 + 2
)

// Serialize encodes the record for persistence.
func (r *Record) Serialize() ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: sender key record is nil", signalerrors.ErrInvalidMessage)
	}

	maxStates := r.maxStates
	if maxStates <= 0 {
		maxStates = DefaultMaxStates
	}

	states := r.states
	if len(states) > maxStates {
		states = states[:maxStates]
	}

	out := make([]byte, 0, recordMinSize+len(states)*64)
	out = append(out, recordSerializeMagic[:]...)
	out = append(out, recordSerializeVersion)
	out = binary.BigEndian.AppendUint16(out, uint16(maxStates))
	out = binary.BigEndian.AppendUint16(out, uint16(len(states)))

	for _, st := range states {
		if st == nil {
			return nil, fmt.Errorf("%w: sender key record contains nil state", signalerrors.ErrInvalidMessage)
		}

		out = append(out, st.messageVersion)
		out = append(out, st.distributionID[:]...)
		out = binary.BigEndian.AppendUint32(out, st.keyID)
		out = binary.BigEndian.AppendUint32(out, st.chainIteration)
		out = append(out, st.chainSeed[:]...)
		out = append(out, st.signingPublic[:]...)

		if st.hasPrivate {
			out = append(out, byte(1))
			out = append(out, st.signingPrivateSeed[:]...)
		} else {
			out = append(out, byte(0))
		}

		msgKeys := st.messageKeys
		if len(msgKeys) > maxMessageKeysPerState {
			msgKeys = msgKeys[len(msgKeys)-maxMessageKeysPerState:]
		}

		out = binary.BigEndian.AppendUint16(out, uint16(len(msgKeys)))
		for _, mk := range msgKeys {
			out = binary.BigEndian.AppendUint32(out, mk.iteration)
			out = append(out, mk.seed[:]...)
		}
	}

	return out, nil
}

// DeserializeRecord reconstructs a Record from serialized bytes.
func DeserializeRecord(data []byte) (*Record, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: sender key record: empty data", signalerrors.ErrInvalidMessage)
	}
	if len(data) < recordMinSize ||
		data[0] != recordSerializeMagic[0] ||
		data[1] != recordSerializeMagic[1] ||
		data[2] != recordSerializeMagic[2] ||
		data[3] != recordSerializeMagic[3] {
		return nil, fmt.Errorf("%w: sender key record: unsupported format", signalerrors.ErrInvalidMessage)
	}

	pos := 0
	pos += 4
	version := data[pos]
	pos++
	if version != recordSerializeVersion && version != 1 {
		return nil, fmt.Errorf("%w: sender key record: unsupported version %d", signalerrors.ErrInvalidMessage, version)
	}
	if pos+2+2 > len(data) {
		return nil, fmt.Errorf("%w: sender key record: truncated header", signalerrors.ErrInvalidMessage)
	}

	maxStates := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	if maxStates <= 0 {
		maxStates = DefaultMaxStates
	}

	stateCount := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2

	rec := &Record{
		maxStates: maxStates,
	}

	for i := 0; i < stateCount; i++ {
		var messageVersion uint8 = senderKeyMessageVersion
		var distributionID [distributionIDSize]byte

		if version == recordSerializeVersion {
			const fixedSize = 1 + distributionIDSize + 4 + 4 + senderKeySeedSize + 32 + 1 + 2
			if pos+fixedSize > len(data) {
				return nil, fmt.Errorf("%w: sender key record: truncated state", signalerrors.ErrInvalidMessage)
			}
			messageVersion = data[pos]
			pos++
			copy(distributionID[:], data[pos:pos+distributionIDSize])
			pos += distributionIDSize
		} else {
			const fixedSize = 4 + 4 + senderKeySeedSize + 32 + 1 + 2
			if pos+fixedSize > len(data) {
				return nil, fmt.Errorf("%w: sender key record: truncated state", signalerrors.ErrInvalidMessage)
			}
		}

		keyID := binary.BigEndian.Uint32(data[pos : pos+4])
		pos += 4
		chainIteration := binary.BigEndian.Uint32(data[pos : pos+4])
		pos += 4

		var chainSeed [senderKeySeedSize]byte
		copy(chainSeed[:], data[pos:pos+senderKeySeedSize])
		pos += senderKeySeedSize

		var signingPublic [32]byte
		copy(signingPublic[:], data[pos:pos+32])
		pos += 32

		hasPrivate := data[pos]
		pos++

		var signingPrivateSeed [32]byte
		privateOK := false
		switch hasPrivate {
		case 0:
			privateOK = false
		case 1:
			if pos+32 > len(data) {
				return nil, fmt.Errorf("%w: sender key record: truncated signing private key", signalerrors.ErrInvalidMessage)
			}
			copy(signingPrivateSeed[:], data[pos:pos+32])
			pos += 32
			privateOK = true
		default:
			return nil, fmt.Errorf("%w: sender key record: invalid signing key flag", signalerrors.ErrInvalidMessage)
		}

		if pos+2 > len(data) {
			return nil, fmt.Errorf("%w: sender key record: truncated message keys count", signalerrors.ErrInvalidMessage)
		}
		messageKeyCount := int(binary.BigEndian.Uint16(data[pos : pos+2]))
		pos += 2
		if messageKeyCount < 0 || messageKeyCount > maxMessageKeysPerState {
			return nil, fmt.Errorf("%w: sender key record: invalid message keys count", signalerrors.ErrInvalidMessage)
		}

		state := &state{
			messageVersion:     messageVersion,
			distributionID:     distributionID,
			keyID:              keyID,
			chainIteration:     chainIteration,
			chainSeed:          chainSeed,
			signingPublic:      signingPublic,
			signingPrivateSeed: signingPrivateSeed,
			hasPrivate:         privateOK,
		}

		if messageKeyCount > 0 {
			state.messageKeys = make([]messageKey, 0, messageKeyCount)
		}

		for j := 0; j < messageKeyCount; j++ {
			const mkSize = 4 + senderKeySeedSize
			if pos+mkSize > len(data) {
				return nil, fmt.Errorf("%w: sender key record: truncated message key", signalerrors.ErrInvalidMessage)
			}

			iteration := binary.BigEndian.Uint32(data[pos : pos+4])
			pos += 4
			var mkSeed [senderKeySeedSize]byte
			copy(mkSeed[:], data[pos:pos+senderKeySeedSize])
			pos += senderKeySeedSize

			state.messageKeys = append(state.messageKeys, messageKey{
				iteration: iteration,
				seed:      mkSeed,
			})
		}

		if len(rec.states) < rec.maxStates {
			rec.states = append(rec.states, state)
		}
	}

	if pos != len(data) {
		return nil, fmt.Errorf("%w: sender key record: trailing data", signalerrors.ErrInvalidMessage)
	}

	return rec, nil
}
