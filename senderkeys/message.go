package senderkeys

import (
	"fmt"

	"google.golang.org/protobuf/encoding/protowire"

	signalerrors "github.com/deicod/signal/errors"
	"github.com/deicod/signal/keys"
)

const (
	senderKeyMessageVersion uint8 = 3
	senderKeySignatureSize        = 64
)

type distributionMessage struct {
	messageVersion uint8
	distributionID [distributionIDSize]byte
	keyID          uint32
	iteration      uint32
	chainKey       [senderKeySeedSize]byte
	signingPublic  [32]byte
}

func (m distributionMessage) serialize() []byte {
	body := encodeSenderKeyDistributionBody(m.distributionID, m.keyID, m.iteration, m.chainKey, m.signingPublic)
	out := make([]byte, 0, 1+len(body))
	out = append(out, senderKeyVersionByte(m.messageVersion))
	out = append(out, body...)
	return out
}

func parseDistributionMessage(data []byte) (*distributionMessage, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("%w: sender key distribution message too short", signalerrors.ErrInvalidMessage)
	}
	version := parseSenderKeyVersion(data[0])
	if version < senderKeyMessageVersion {
		return nil, fmt.Errorf("%w: legacy sender key distribution version %d", signalerrors.ErrInvalidMessage, version)
	}
	if version > senderKeyMessageVersion {
		return nil, fmt.Errorf("%w: unsupported sender key distribution version %d", signalerrors.ErrInvalidMessage, version)
	}

	distributionID, keyID, iteration, chainKey, signingPublic, err := decodeSenderKeyDistributionBody(data[1:])
	if err != nil {
		return nil, err
	}

	return &distributionMessage{
		messageVersion: version,
		distributionID: distributionID,
		keyID:          keyID,
		iteration:      iteration,
		chainKey:       chainKey,
		signingPublic:  signingPublic,
	}, nil
}

type senderKeyMessage struct {
	messageVersion uint8
	distributionID [distributionIDSize]byte
	keyID          uint32
	iteration      uint32
	ciphertext     []byte
	signature      [senderKeySignatureSize]byte
}

func (m senderKeyMessage) serialize() []byte {
	body := encodeSenderKeyMessageBody(m.distributionID, m.keyID, m.iteration, m.ciphertext)
	out := make([]byte, 0, 1+len(body)+senderKeySignatureSize)
	out = append(out, senderKeyVersionByte(m.messageVersion))
	out = append(out, body...)
	out = append(out, m.signature[:]...)
	return out
}

func (m senderKeyMessage) signedBytes() []byte {
	body := encodeSenderKeyMessageBody(m.distributionID, m.keyID, m.iteration, m.ciphertext)
	out := make([]byte, 0, 1+len(body))
	out = append(out, senderKeyVersionByte(m.messageVersion))
	out = append(out, body...)
	return out
}

func parseSenderKeyMessage(data []byte) (*senderKeyMessage, []byte, error) {
	if len(data) < 1+senderKeySignatureSize {
		return nil, nil, fmt.Errorf("%w: sender key message too short", signalerrors.ErrInvalidMessage)
	}
	version := parseSenderKeyVersion(data[0])
	if version < senderKeyMessageVersion {
		return nil, nil, fmt.Errorf("%w: legacy sender key version %d", signalerrors.ErrInvalidMessage, version)
	}
	if version > senderKeyMessageVersion {
		return nil, nil, fmt.Errorf("%w: unsupported sender key version %d", signalerrors.ErrInvalidMessage, version)
	}

	body := data[1 : len(data)-senderKeySignatureSize]
	distributionID, keyID, iteration, ciphertext, err := decodeSenderKeyMessageBody(body)
	if err != nil {
		return nil, nil, err
	}

	var sig [senderKeySignatureSize]byte
	copy(sig[:], data[len(data)-senderKeySignatureSize:])

	return &senderKeyMessage{
		messageVersion: version,
		distributionID: distributionID,
		keyID:          keyID,
		iteration:      iteration,
		ciphertext:     ciphertext,
		signature:      sig,
	}, data[:len(data)-senderKeySignatureSize], nil
}

func senderKeyVersionByte(messageVersion uint8) byte {
	return byte(((messageVersion & 0x0f) << 4) | (senderKeyMessageVersion & 0x0f))
}

func parseSenderKeyVersion(b byte) uint8 {
	return b >> 4
}

func encodeSenderKeyMessageBody(distributionID [distributionIDSize]byte, keyID uint32, iteration uint32, ciphertext []byte) []byte {
	out := make([]byte, 0, 64+len(ciphertext))
	out = protowire.AppendTag(out, 1, protowire.BytesType)
	out = protowire.AppendBytes(out, distributionID[:])
	out = protowire.AppendTag(out, 2, protowire.VarintType)
	out = protowire.AppendVarint(out, uint64(keyID))
	out = protowire.AppendTag(out, 3, protowire.VarintType)
	out = protowire.AppendVarint(out, uint64(iteration))
	out = protowire.AppendTag(out, 4, protowire.BytesType)
	out = protowire.AppendBytes(out, ciphertext)
	return out
}

func decodeSenderKeyMessageBody(data []byte) (distributionID [distributionIDSize]byte, keyID uint32, iteration uint32, ciphertext []byte, err error) {
	var (
		gotDistributionID bool
		gotChainID        bool
		gotIteration      bool
		gotCiphertext     bool
	)

	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return distributionID, 0, 0, nil, fmt.Errorf("%w: sender key tag", signalerrors.ErrInvalidMessage)
		}
		data = data[n:]
		switch num {
		case 1: // distribution_uuid
			if typ != protowire.BytesType {
				return distributionID, 0, 0, nil, fmt.Errorf("%w: sender key distribution id type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return distributionID, 0, 0, nil, fmt.Errorf("%w: sender key distribution id", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
			if len(val) != distributionIDSize {
				return distributionID, 0, 0, nil, fmt.Errorf("%w: sender key distribution id length %d", signalerrors.ErrInvalidMessage, len(val))
			}
			copy(distributionID[:], val)
			gotDistributionID = true
		case 2: // chain_id
			if typ != protowire.VarintType {
				return distributionID, 0, 0, nil, fmt.Errorf("%w: sender key chain id type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return distributionID, 0, 0, nil, fmt.Errorf("%w: sender key chain id", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
			keyID = uint32(val)
			gotChainID = true
		case 3: // iteration
			if typ != protowire.VarintType {
				return distributionID, 0, 0, nil, fmt.Errorf("%w: sender key iteration type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return distributionID, 0, 0, nil, fmt.Errorf("%w: sender key iteration", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
			iteration = uint32(val)
			gotIteration = true
		case 4: // ciphertext
			if typ != protowire.BytesType {
				return distributionID, 0, 0, nil, fmt.Errorf("%w: sender key ciphertext type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return distributionID, 0, 0, nil, fmt.Errorf("%w: sender key ciphertext", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
			ciphertext = append([]byte(nil), val...)
			gotCiphertext = true
		default:
			if typ == protowire.BytesType {
				_, n = protowire.ConsumeBytes(data)
			} else {
				_, n = protowire.ConsumeVarint(data)
			}
			if n < 0 {
				return distributionID, 0, 0, nil, fmt.Errorf("%w: sender key unknown field", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
		}
	}

	if !gotDistributionID || !gotChainID || !gotIteration || !gotCiphertext {
		return distributionID, 0, 0, nil, fmt.Errorf("%w: sender key missing fields", signalerrors.ErrInvalidMessage)
	}
	return distributionID, keyID, iteration, ciphertext, nil
}

func encodeSenderKeyDistributionBody(distributionID [distributionIDSize]byte, keyID uint32, iteration uint32, chainKey [senderKeySeedSize]byte, signingPublic [32]byte) []byte {
	out := make([]byte, 0, 96)
	out = protowire.AppendTag(out, 1, protowire.BytesType)
	out = protowire.AppendBytes(out, distributionID[:])
	out = protowire.AppendTag(out, 2, protowire.VarintType)
	out = protowire.AppendVarint(out, uint64(keyID))
	out = protowire.AppendTag(out, 3, protowire.VarintType)
	out = protowire.AppendVarint(out, uint64(iteration))
	out = protowire.AppendTag(out, 4, protowire.BytesType)
	out = protowire.AppendBytes(out, chainKey[:])
	out = protowire.AppendTag(out, 5, protowire.BytesType)
	out = protowire.AppendBytes(out, keys.SerializeWirePublicKey(signingPublic))
	return out
}

func decodeSenderKeyDistributionBody(data []byte) (distributionID [distributionIDSize]byte, keyID uint32, iteration uint32, chainKey [senderKeySeedSize]byte, signingPublic [32]byte, err error) {
	var (
		gotDistributionID bool
		gotChainID        bool
		gotIteration      bool
		gotChainKey       bool
		gotSigningKey     bool
	)

	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return distributionID, 0, 0, chainKey, signingPublic, fmt.Errorf("%w: sender key distribution tag", signalerrors.ErrInvalidMessage)
		}
		data = data[n:]
		switch num {
		case 1: // distribution_uuid
			if typ != protowire.BytesType {
				return distributionID, 0, 0, chainKey, signingPublic, fmt.Errorf("%w: sender key distribution id type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return distributionID, 0, 0, chainKey, signingPublic, fmt.Errorf("%w: sender key distribution id", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
			if len(val) != distributionIDSize {
				return distributionID, 0, 0, chainKey, signingPublic, fmt.Errorf("%w: sender key distribution id length %d", signalerrors.ErrInvalidMessage, len(val))
			}
			copy(distributionID[:], val)
			gotDistributionID = true
		case 2: // chain_id
			if typ != protowire.VarintType {
				return distributionID, 0, 0, chainKey, signingPublic, fmt.Errorf("%w: sender key chain id type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return distributionID, 0, 0, chainKey, signingPublic, fmt.Errorf("%w: sender key chain id", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
			keyID = uint32(val)
			gotChainID = true
		case 3: // iteration
			if typ != protowire.VarintType {
				return distributionID, 0, 0, chainKey, signingPublic, fmt.Errorf("%w: sender key iteration type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return distributionID, 0, 0, chainKey, signingPublic, fmt.Errorf("%w: sender key iteration", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
			iteration = uint32(val)
			gotIteration = true
		case 4: // chain_key
			if typ != protowire.BytesType {
				return distributionID, 0, 0, chainKey, signingPublic, fmt.Errorf("%w: sender key chain key type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return distributionID, 0, 0, chainKey, signingPublic, fmt.Errorf("%w: sender key chain key", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
			if len(val) != senderKeySeedSize {
				return distributionID, 0, 0, chainKey, signingPublic, fmt.Errorf("%w: sender key chain key length %d", signalerrors.ErrInvalidMessage, len(val))
			}
			copy(chainKey[:], val)
			gotChainKey = true
		case 5: // signing_key
			if typ != protowire.BytesType {
				return distributionID, 0, 0, chainKey, signingPublic, fmt.Errorf("%w: sender key signing key type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return distributionID, 0, 0, chainKey, signingPublic, fmt.Errorf("%w: sender key signing key", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
			key, err := keys.DeserializeWirePublicKey(val)
			if err != nil {
				return distributionID, 0, 0, chainKey, signingPublic, err
			}
			signingPublic = key
			gotSigningKey = true
		default:
			if typ == protowire.BytesType {
				_, n = protowire.ConsumeBytes(data)
			} else {
				_, n = protowire.ConsumeVarint(data)
			}
			if n < 0 {
				return distributionID, 0, 0, chainKey, signingPublic, fmt.Errorf("%w: sender key distribution unknown field", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
		}
	}

	if !gotDistributionID || !gotChainID || !gotIteration || !gotChainKey || !gotSigningKey {
		return distributionID, 0, 0, chainKey, signingPublic, fmt.Errorf("%w: sender key distribution missing fields", signalerrors.ErrInvalidMessage)
	}
	return distributionID, keyID, iteration, chainKey, signingPublic, nil
}
