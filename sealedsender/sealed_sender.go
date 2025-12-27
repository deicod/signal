package sealedsender

import (
	"crypto/subtle"
	"fmt"

	signalcrypto "github.com/deicod/signal/crypto"
	signalerrors "github.com/deicod/signal/errors"
	"github.com/deicod/signal/keys"
	"google.golang.org/protobuf/encoding/protowire"
)

const (
	sealedSenderV1MajorVersion         uint8 = 1
	sealedSenderV1FullVersion          uint8 = 0x11
	sealedSenderV2MajorVersion         uint8 = 2
	sealedSenderV2UUIDFullVersion      uint8 = 0x22
	sealedSenderV2ServiceIDFullVersion uint8 = 0x23
)

const (
	sealedSenderV2MessageKeyLen = 32
	sealedSenderV2AuthTagLen    = 16
	sealedSenderV2PublicKeyLen  = 32
)

var (
	sealedSenderSaltPrefix = []byte("UnidentifiedDelivery")
	sealedSenderV2LabelR   = []byte("Sealed Sender v2: r (2023-08)")
	sealedSenderV2LabelK   = []byte("Sealed Sender v2: K")
	sealedSenderV2LabelDH  = []byte("Sealed Sender v2: DH")
	sealedSenderV2LabelDHS = []byte("Sealed Sender v2: DH-sender")
)

type direction int

const (
	directionSending direction = iota
	directionReceiving
)

type ephemeralKeys struct {
	chainKey  [32]byte
	cipherKey [32]byte
	macKey    [32]byte
}

type staticKeys struct {
	cipherKey [32]byte
	macKey    [32]byte
}

type sealedSenderV1Message struct {
	ephemeralPublic  []byte
	encryptedStatic  []byte
	encryptedMessage []byte
}

// EncryptV1 encrypts sealed sender content using the v1 format.
func EncryptV1(recipientIdentity [32]byte, senderIdentity *keys.IdentityKeyPair, usmc *UnidentifiedSenderMessageContent) ([]byte, error) {
	if senderIdentity == nil {
		return nil, fmt.Errorf("%w: sender identity is nil", signalerrors.ErrInvalidKey)
	}
	if usmc == nil || usmc.sender == nil {
		return nil, fmt.Errorf("%w: content is nil", signalerrors.ErrInvalidMessage)
	}
	if !compareIdentityKeyBytes(usmc.sender.identityKeyBytes, senderIdentity.PublicKey.PublicKey) {
		return nil, fmt.Errorf("%w: sender certificate does not match identity", signalerrors.ErrInvalidKey)
	}

	ephemeral, err := signalcrypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("sealed sender: generate ephemeral: %w", err)
	}

	ephKeys, err := deriveEphemeralKeys(ephemeral.PublicKey, ephemeral.PrivateKey, recipientIdentity, directionSending)
	if err != nil {
		return nil, err
	}

	encryptedStatic, err := signalcrypto.AES256CTRHMACSHA256Encrypt(
		keys.SerializeWirePublicKey(senderIdentity.PublicKey.PublicKey),
		ephKeys.cipherKey[:],
		ephKeys.macKey[:],
	)
	if err != nil {
		return nil, fmt.Errorf("sealed sender: encrypt static: %w", err)
	}

	staticKeys, err := deriveStaticKeys(senderIdentity.PrivateKey, recipientIdentity, ephKeys.chainKey, encryptedStatic)
	if err != nil {
		return nil, err
	}

	encryptedMessage, err := signalcrypto.AES256CTRHMACSHA256Encrypt(
		usmc.Serialize(),
		staticKeys.cipherKey[:],
		staticKeys.macKey[:],
	)
	if err != nil {
		return nil, fmt.Errorf("sealed sender: encrypt message: %w", err)
	}

	msg := encodeSealedSenderV1Message(keys.SerializeWirePublicKey(ephemeral.PublicKey), encryptedStatic, encryptedMessage)
	out := make([]byte, 0, 1+len(msg))
	out = append(out, sealedSenderV1FullVersion)
	out = append(out, msg...)
	return out, nil
}

// EncryptV2Received encrypts sealed sender content using the v2 ReceivedMessage format.
func EncryptV2Received(recipientIdentity [32]byte, senderIdentity *keys.IdentityKeyPair, usmc *UnidentifiedSenderMessageContent) ([]byte, error) {
	if senderIdentity == nil {
		return nil, fmt.Errorf("%w: sender identity is nil", signalerrors.ErrInvalidKey)
	}
	if usmc == nil || usmc.sender == nil {
		return nil, fmt.Errorf("%w: content is nil", signalerrors.ErrInvalidMessage)
	}
	if !compareIdentityKeyBytes(usmc.sender.identityKeyBytes, senderIdentity.PublicKey.PublicKey) {
		return nil, fmt.Errorf("%w: sender certificate does not match identity", signalerrors.ErrInvalidKey)
	}

	mBytes, err := signalcrypto.RandomBytes(sealedSenderV2MessageKeyLen)
	if err != nil {
		return nil, fmt.Errorf("sealed sender v2: random: %w", err)
	}
	var m [sealedSenderV2MessageKeyLen]byte
	copy(m[:], mBytes)

	rBytes, err := signalcrypto.HKDF(mBytes, nil, sealedSenderV2LabelR, sealedSenderV2MessageKeyLen)
	if err != nil {
		return nil, fmt.Errorf("sealed sender v2: derive r: %w", err)
	}
	kBytes, err := signalcrypto.HKDF(mBytes, nil, sealedSenderV2LabelK, sealedSenderV2MessageKeyLen)
	if err != nil {
		return nil, fmt.Errorf("sealed sender v2: derive k: %w", err)
	}

	var r [sealedSenderV2MessageKeyLen]byte
	copy(r[:], rBytes)
	ephemeral, err := signalcrypto.KeyPairFromPrivate(r)
	if err != nil {
		return nil, fmt.Errorf("sealed sender v2: derive ephemeral: %w", err)
	}

	c, err := applyAgreementXOR(ephemeral.PrivateKey, ephemeral.PublicKey, recipientIdentity, directionSending, m)
	if err != nil {
		return nil, err
	}
	at, err := computeAuthenticationTag(senderIdentity.PrivateKey, senderIdentity.PublicKey.PublicKey, recipientIdentity, directionSending, ephemeral.PublicKey, c)
	if err != nil {
		return nil, err
	}

	zeroNonce := make([]byte, signalcrypto.AESGCMSIVNonceSize)
	ciphertext, err := signalcrypto.AESGCMSIVEncrypt(kBytes, zeroNonce, usmc.Serialize(), nil)
	if err != nil {
		return nil, fmt.Errorf("sealed sender v2: encrypt: %w", err)
	}

	out := make([]byte, 0, 1+sealedSenderV2MessageKeyLen+sealedSenderV2AuthTagLen+sealedSenderV2PublicKeyLen+len(ciphertext))
	out = append(out, sealedSenderV2UUIDFullVersion)
	out = append(out, c[:]...)
	out = append(out, at[:]...)
	out = append(out, ephemeral.PublicKey[:]...)
	out = append(out, ciphertext...)
	return out, nil
}

// DecryptToUSMC decrypts a sealed sender message and returns the inner content.
func DecryptToUSMC(ciphertext []byte, recipientIdentity *keys.IdentityKeyPair) (*UnidentifiedSenderMessageContent, error) {
	if recipientIdentity == nil {
		return nil, fmt.Errorf("%w: recipient identity is nil", signalerrors.ErrInvalidKey)
	}
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("%w: sealed sender message empty", signalerrors.ErrInvalidMessage)
	}

	version := ciphertext[0] >> 4
	switch version {
	case 0, sealedSenderV1MajorVersion:
		return decryptV1(ciphertext[1:], recipientIdentity)
	case sealedSenderV2MajorVersion:
		return decryptV2(ciphertext[1:], recipientIdentity)
	default:
		return nil, fmt.Errorf("%w: unsupported sealed sender version %d", signalerrors.ErrInvalidMessage, version)
	}
}

func decryptV1(payload []byte, recipientIdentity *keys.IdentityKeyPair) (*UnidentifiedSenderMessageContent, error) {
	msg, err := decodeSealedSenderV1Message(payload)
	if err != nil {
		return nil, err
	}
	if len(msg.ephemeralPublic) == 0 {
		return nil, fmt.Errorf("%w: sealed sender missing ephemeral key", signalerrors.ErrInvalidMessage)
	}
	if len(msg.encryptedStatic) == 0 || len(msg.encryptedMessage) == 0 {
		return nil, fmt.Errorf("%w: sealed sender missing ciphertext", signalerrors.ErrInvalidMessage)
	}

	ephemeralPub, err := keys.DeserializeWirePublicKey(msg.ephemeralPublic)
	if err != nil {
		return nil, err
	}

	ephKeys, err := deriveEphemeralKeys(recipientIdentity.PublicKey.PublicKey, recipientIdentity.PrivateKey, ephemeralPub, directionReceiving)
	if err != nil {
		return nil, err
	}

	messageKeyBytes, err := signalcrypto.AES256CTRHMACSHA256Decrypt(msg.encryptedStatic, ephKeys.cipherKey[:], ephKeys.macKey[:])
	if err != nil {
		return nil, fmt.Errorf("%w: sealed sender static key", signalerrors.ErrInvalidMAC)
	}

	staticKey, err := keys.DeserializeWirePublicKey(messageKeyBytes)
	if err != nil {
		return nil, err
	}

	staticKeys, err := deriveStaticKeys(recipientIdentity.PrivateKey, staticKey, ephKeys.chainKey, msg.encryptedStatic)
	if err != nil {
		return nil, err
	}

	messageBytes, err := signalcrypto.AES256CTRHMACSHA256Decrypt(msg.encryptedMessage, staticKeys.cipherKey[:], staticKeys.macKey[:])
	if err != nil {
		return nil, fmt.Errorf("%w: sealed sender message", signalerrors.ErrInvalidMAC)
	}

	usmc, err := ParseUnidentifiedSenderMessageContent(messageBytes)
	if err != nil {
		return nil, err
	}

	if usmc.sender == nil {
		return nil, fmt.Errorf("%w: sealed sender missing sender", signalerrors.ErrInvalidMessage)
	}
	if subtle.ConstantTimeCompare(messageKeyBytes, usmc.sender.identityKeyBytes) != 1 {
		return nil, fmt.Errorf("%w: sealed sender sender key mismatch", signalerrors.ErrInvalidMessage)
	}

	return usmc, nil
}

func decryptV2(payload []byte, recipientIdentity *keys.IdentityKeyPair) (*UnidentifiedSenderMessageContent, error) {
	minSize := sealedSenderV2MessageKeyLen + sealedSenderV2AuthTagLen + sealedSenderV2PublicKeyLen + sealedSenderV2AuthTagLen
	if len(payload) < minSize {
		return nil, fmt.Errorf("%w: sealed sender v2 too short", signalerrors.ErrInvalidMessage)
	}

	var (
		c    [sealedSenderV2MessageKeyLen]byte
		at   [sealedSenderV2AuthTagLen]byte
		epub [sealedSenderV2PublicKeyLen]byte
	)
	off := 0
	copy(c[:], payload[off:off+sealedSenderV2MessageKeyLen])
	off += sealedSenderV2MessageKeyLen
	copy(at[:], payload[off:off+sealedSenderV2AuthTagLen])
	off += sealedSenderV2AuthTagLen
	copy(epub[:], payload[off:off+sealedSenderV2PublicKeyLen])
	off += sealedSenderV2PublicKeyLen
	encrypted := payload[off:]

	m, err := applyAgreementXOR(recipientIdentity.PrivateKey, recipientIdentity.PublicKey.PublicKey, epub, directionReceiving, c)
	if err != nil {
		return nil, err
	}

	rBytes, err := signalcrypto.HKDF(m[:], nil, sealedSenderV2LabelR, sealedSenderV2MessageKeyLen)
	if err != nil {
		return nil, fmt.Errorf("sealed sender v2: derive r: %w", err)
	}
	kBytes, err := signalcrypto.HKDF(m[:], nil, sealedSenderV2LabelK, sealedSenderV2MessageKeyLen)
	if err != nil {
		return nil, fmt.Errorf("sealed sender v2: derive k: %w", err)
	}

	var r [sealedSenderV2MessageKeyLen]byte
	copy(r[:], rBytes)
	ephemeral, err := signalcrypto.KeyPairFromPrivate(r)
	if err != nil {
		return nil, fmt.Errorf("sealed sender v2: derive ephemeral: %w", err)
	}
	if subtle.ConstantTimeCompare(ephemeral.PublicKey[:], epub[:]) != 1 {
		return nil, fmt.Errorf("%w: sealed sender v2 invalid ephemeral key", signalerrors.ErrInvalidMessage)
	}

	zeroNonce := make([]byte, signalcrypto.AESGCMSIVNonceSize)
	messageBytes, err := signalcrypto.AESGCMSIVDecrypt(kBytes, zeroNonce, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: sealed sender v2 decrypt", signalerrors.ErrInvalidMAC)
	}

	usmc, err := ParseUnidentifiedSenderMessageContent(messageBytes)
	if err != nil {
		return nil, err
	}
	if usmc.sender == nil {
		return nil, fmt.Errorf("%w: sealed sender missing sender", signalerrors.ErrInvalidMessage)
	}

	atCalc, err := computeAuthenticationTag(recipientIdentity.PrivateKey, recipientIdentity.PublicKey.PublicKey, usmc.sender.identityKey, directionReceiving, epub, c)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(at[:], atCalc[:]) != 1 {
		return nil, fmt.Errorf("%w: sealed sender v2 authentication tag", signalerrors.ErrInvalidMessage)
	}

	return usmc, nil
}

func deriveEphemeralKeys(ourPublic, ourPrivate, theirPublic [32]byte, dir direction) (*ephemeralKeys, error) {
	ourWire := keys.SerializeWirePublicKey(ourPublic)
	theirWire := keys.SerializeWirePublicKey(theirPublic)
	var salt []byte
	if dir == directionSending {
		salt = append(append(append([]byte(nil), sealedSenderSaltPrefix...), theirWire...), ourWire...)
	} else {
		salt = append(append(append([]byte(nil), sealedSenderSaltPrefix...), ourWire...), theirWire...)
	}

	shared, err := signalcrypto.DH(ourPrivate, theirPublic)
	if err != nil {
		return nil, fmt.Errorf("sealed sender: dh: %w", err)
	}

	okm, err := signalcrypto.HKDF(shared[:], salt, nil, 96)
	if err != nil {
		return nil, fmt.Errorf("sealed sender: hkdf: %w", err)
	}

	var out ephemeralKeys
	copy(out.chainKey[:], okm[0:32])
	copy(out.cipherKey[:], okm[32:64])
	copy(out.macKey[:], okm[64:96])
	return &out, nil
}

func deriveStaticKeys(ourPrivate [32]byte, theirPublic [32]byte, chainKey [32]byte, encryptedStatic []byte) (*staticKeys, error) {
	salt := make([]byte, 0, 32+len(encryptedStatic))
	salt = append(salt, chainKey[:]...)
	salt = append(salt, encryptedStatic...)

	shared, err := signalcrypto.DH(ourPrivate, theirPublic)
	if err != nil {
		return nil, fmt.Errorf("sealed sender: dh: %w", err)
	}

	okm, err := signalcrypto.HKDF(shared[:], salt, nil, 96)
	if err != nil {
		return nil, fmt.Errorf("sealed sender: hkdf: %w", err)
	}

	var out staticKeys
	copy(out.cipherKey[:], okm[32:64])
	copy(out.macKey[:], okm[64:96])
	return &out, nil
}

func encodeSealedSenderV1Message(ephemeralPublic, encryptedStatic, encryptedMessage []byte) []byte {
	out := make([]byte, 0, len(ephemeralPublic)+len(encryptedStatic)+len(encryptedMessage)+16)
	out = protowire.AppendTag(out, 1, protowire.BytesType)
	out = protowire.AppendBytes(out, ephemeralPublic)
	out = protowire.AppendTag(out, 2, protowire.BytesType)
	out = protowire.AppendBytes(out, encryptedStatic)
	out = protowire.AppendTag(out, 3, protowire.BytesType)
	out = protowire.AppendBytes(out, encryptedMessage)
	return out
}

func decodeSealedSenderV1Message(data []byte) (*sealedSenderV1Message, error) {
	var (
		ephemeralPublic  []byte
		encryptedStatic  []byte
		encryptedMessage []byte
		gotEphemeral     bool
		gotStatic        bool
		gotMessage       bool
	)

	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return nil, fmt.Errorf("%w: sealed sender tag", signalerrors.ErrInvalidMessage)
		}
		data = data[n:]
		switch num {
		case 1: // ephemeral_public
			if typ != protowire.BytesType {
				return nil, fmt.Errorf("%w: sealed sender ephemeral type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, fmt.Errorf("%w: sealed sender ephemeral", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
			ephemeralPublic = append([]byte(nil), val...)
			gotEphemeral = true
		case 2: // encrypted_static
			if typ != protowire.BytesType {
				return nil, fmt.Errorf("%w: sealed sender encrypted static type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, fmt.Errorf("%w: sealed sender encrypted static", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
			encryptedStatic = append([]byte(nil), val...)
			gotStatic = true
		case 3: // encrypted_message
			if typ != protowire.BytesType {
				return nil, fmt.Errorf("%w: sealed sender encrypted message type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, fmt.Errorf("%w: sealed sender encrypted message", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
			encryptedMessage = append([]byte(nil), val...)
			gotMessage = true
		default:
			n := protowire.ConsumeFieldValue(num, typ, data)
			if n < 0 {
				return nil, fmt.Errorf("%w: sealed sender field", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
		}
	}

	if !gotEphemeral || !gotStatic || !gotMessage {
		return nil, fmt.Errorf("%w: sealed sender missing fields", signalerrors.ErrInvalidMessage)
	}

	return &sealedSenderV1Message{
		ephemeralPublic:  ephemeralPublic,
		encryptedStatic:  encryptedStatic,
		encryptedMessage: encryptedMessage,
	}, nil
}

func applyAgreementXOR(ourPrivate, ourPublic, theirPublic [32]byte, dir direction, input [sealedSenderV2MessageKeyLen]byte) ([sealedSenderV2MessageKeyLen]byte, error) {
	shared, err := signalcrypto.DH(ourPrivate, theirPublic)
	if err != nil {
		return [sealedSenderV2MessageKeyLen]byte{}, fmt.Errorf("sealed sender v2: dh: %w", err)
	}

	buf := make([]byte, 0, 32+33+33)
	buf = append(buf, shared[:]...)
	if dir == directionSending {
		buf = append(buf, keys.SerializeWirePublicKey(ourPublic)...)
		buf = append(buf, keys.SerializeWirePublicKey(theirPublic)...)
	} else {
		buf = append(buf, keys.SerializeWirePublicKey(theirPublic)...)
		buf = append(buf, keys.SerializeWirePublicKey(ourPublic)...)
	}

	mask, err := signalcrypto.HKDF(buf, nil, sealedSenderV2LabelDH, sealedSenderV2MessageKeyLen)
	if err != nil {
		return [sealedSenderV2MessageKeyLen]byte{}, fmt.Errorf("sealed sender v2: hkdf: %w", err)
	}

	var out [sealedSenderV2MessageKeyLen]byte
	for i := 0; i < len(out); i++ {
		out[i] = mask[i] ^ input[i]
	}
	return out, nil
}

func computeAuthenticationTag(ourPrivate, ourPublic, theirPublic [32]byte, dir direction, ephemeralPublic [32]byte, encryptedMessageKey [sealedSenderV2MessageKeyLen]byte) ([sealedSenderV2AuthTagLen]byte, error) {
	shared, err := signalcrypto.DH(ourPrivate, theirPublic)
	if err != nil {
		return [sealedSenderV2AuthTagLen]byte{}, fmt.Errorf("sealed sender v2: dh: %w", err)
	}

	buf := make([]byte, 0, 32+33+sealedSenderV2MessageKeyLen+33+33)
	buf = append(buf, shared[:]...)
	buf = append(buf, keys.SerializeWirePublicKey(ephemeralPublic)...)
	buf = append(buf, encryptedMessageKey[:]...)
	if dir == directionSending {
		buf = append(buf, keys.SerializeWirePublicKey(ourPublic)...)
		buf = append(buf, keys.SerializeWirePublicKey(theirPublic)...)
	} else {
		buf = append(buf, keys.SerializeWirePublicKey(theirPublic)...)
		buf = append(buf, keys.SerializeWirePublicKey(ourPublic)...)
	}

	okm, err := signalcrypto.HKDF(buf, nil, sealedSenderV2LabelDHS, sealedSenderV2AuthTagLen)
	if err != nil {
		return [sealedSenderV2AuthTagLen]byte{}, fmt.Errorf("sealed sender v2: hkdf: %w", err)
	}

	var out [sealedSenderV2AuthTagLen]byte
	copy(out[:], okm)
	return out, nil
}
