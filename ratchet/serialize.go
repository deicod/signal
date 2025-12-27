package ratchet

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"

	signalcrypto "github.com/deicod/signal/crypto"
	signalerrors "github.com/deicod/signal/errors"
)

const stateSerializeVersion byte = 1

// Serialize encodes the ratchet state into a stable, versioned binary format.
func (s *State) Serialize() ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("%w: ratchet state is nil", signalerrors.ErrInvalidMessage)
	}

	flags := byte(0)
	if s.DHs != nil {
		flags |= 1 << 0
	}
	if s.DHr != nil {
		flags |= 1 << 1
	}

	skipped := s.MKSkipped
	if skipped == nil {
		skipped = map[SkippedKey][32]byte{}
	}
	seen := s.SeenDH
	if seen == nil {
		seen = map[[32]byte]struct{}{}
	}

	out := make([]byte, 0, 1+1+64+32+96+12+4+len(skipped)*(32+4+32)+4+len(seen)*32)
	out = append(out, stateSerializeVersion, flags)
	if s.DHs != nil {
		out = append(out, s.DHs.PublicKey[:]...)
		out = append(out, s.DHs.PrivateKey[:]...)
	}
	if s.DHr != nil {
		out = append(out, s.DHr[:]...)
	}
	out = append(out, s.RK[:]...)
	out = append(out, s.CKs[:]...)
	out = append(out, s.CKr[:]...)

	out = binary.BigEndian.AppendUint32(out, s.Ns)
	out = binary.BigEndian.AppendUint32(out, s.Nr)
	out = binary.BigEndian.AppendUint32(out, s.PN)

	entries := make([]SkippedKey, 0, len(skipped))
	for k := range skipped {
		entries = append(entries, k)
	}
	sort.Slice(entries, func(i, j int) bool {
		if c := bytes.Compare(entries[i].PublicKey[:], entries[j].PublicKey[:]); c != 0 {
			return c < 0
		}
		return entries[i].N < entries[j].N
	})

	out = binary.BigEndian.AppendUint32(out, uint32(len(entries)))
	for _, k := range entries {
		out = append(out, k.PublicKey[:]...)
		out = binary.BigEndian.AppendUint32(out, k.N)
		mk := skipped[k]
		out = append(out, mk[:]...)
	}

	seenKeys := make([][32]byte, 0, len(seen))
	for k := range seen {
		seenKeys = append(seenKeys, k)
	}
	sort.Slice(seenKeys, func(i, j int) bool {
		return bytes.Compare(seenKeys[i][:], seenKeys[j][:]) < 0
	})
	out = binary.BigEndian.AppendUint32(out, uint32(len(seenKeys)))
	for _, k := range seenKeys {
		out = append(out, k[:]...)
	}

	return out, nil
}

// DeserializeState decodes a State previously serialized with (*State).Serialize.
func DeserializeState(data []byte) (*State, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("%w: ratchet state too short", signalerrors.ErrInvalidMessage)
	}

	pos := 0
	version := data[pos]
	pos++
	if version != stateSerializeVersion {
		return nil, fmt.Errorf("%w: ratchet state unsupported version %d", signalerrors.ErrInvalidMessage, version)
	}

	flags := data[pos]
	pos++
	hasDHs := flags&(1<<0) != 0
	hasDHr := flags&(1<<1) != 0

	state := &State{
		MKSkipped: make(map[SkippedKey][32]byte),
		SeenDH:    make(map[[32]byte]struct{}),
	}

	if hasDHs {
		if pos+64 > len(data) {
			return nil, fmt.Errorf("%w: ratchet state truncated DHs", signalerrors.ErrInvalidMessage)
		}
		var kp signalcrypto.KeyPair
		copy(kp.PublicKey[:], data[pos:pos+32])
		pos += 32
		copy(kp.PrivateKey[:], data[pos:pos+32])
		pos += 32
		state.DHs = &kp
	}
	if hasDHr {
		if pos+32 > len(data) {
			return nil, fmt.Errorf("%w: ratchet state truncated DHr", signalerrors.ErrInvalidMessage)
		}
		var dhr [32]byte
		copy(dhr[:], data[pos:pos+32])
		pos += 32
		state.DHr = &dhr
	}

	if pos+32*3+4*3 > len(data) {
		return nil, fmt.Errorf("%w: ratchet state truncated keys", signalerrors.ErrInvalidMessage)
	}
	copy(state.RK[:], data[pos:pos+32])
	pos += 32
	copy(state.CKs[:], data[pos:pos+32])
	pos += 32
	copy(state.CKr[:], data[pos:pos+32])
	pos += 32

	state.Ns = binary.BigEndian.Uint32(data[pos : pos+4])
	pos += 4
	state.Nr = binary.BigEndian.Uint32(data[pos : pos+4])
	pos += 4
	state.PN = binary.BigEndian.Uint32(data[pos : pos+4])
	pos += 4

	if pos+4 > len(data) {
		return nil, fmt.Errorf("%w: ratchet state truncated skipped count", signalerrors.ErrInvalidMessage)
	}
	skippedCount := int(binary.BigEndian.Uint32(data[pos : pos+4]))
	pos += 4
	if skippedCount < 0 || skippedCount > MaxSkip {
		return nil, fmt.Errorf("%w: ratchet state invalid skipped count", signalerrors.ErrInvalidMessage)
	}
	for i := 0; i < skippedCount; i++ {
		if pos+32+4+32 > len(data) {
			return nil, fmt.Errorf("%w: ratchet state truncated skipped entry", signalerrors.ErrInvalidMessage)
		}
		var k SkippedKey
		copy(k.PublicKey[:], data[pos:pos+32])
		pos += 32
		k.N = binary.BigEndian.Uint32(data[pos : pos+4])
		pos += 4
		var mk [32]byte
		copy(mk[:], data[pos:pos+32])
		pos += 32
		state.MKSkipped[k] = mk
	}

	if pos+4 > len(data) {
		return nil, fmt.Errorf("%w: ratchet state truncated seen count", signalerrors.ErrInvalidMessage)
	}
	seenCount := int(binary.BigEndian.Uint32(data[pos : pos+4]))
	pos += 4
	if seenCount < 0 {
		return nil, fmt.Errorf("%w: ratchet state invalid seen count", signalerrors.ErrInvalidMessage)
	}
	for i := 0; i < seenCount; i++ {
		if pos+32 > len(data) {
			return nil, fmt.Errorf("%w: ratchet state truncated seen entry", signalerrors.ErrInvalidMessage)
		}
		var k [32]byte
		copy(k[:], data[pos:pos+32])
		pos += 32
		state.SeenDH[k] = struct{}{}
	}

	if pos != len(data) {
		return nil, fmt.Errorf("%w: ratchet state trailing data", signalerrors.ErrInvalidMessage)
	}

	return state, nil
}
