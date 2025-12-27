package sealedsender

import (
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"math"
	"time"

	"google.golang.org/protobuf/encoding/protowire"

	signalcrypto "github.com/deicod/signal/crypto"
	signalerrors "github.com/deicod/signal/errors"
	"github.com/deicod/signal/keys"
)

const revokedServerCertificateID uint32 = 0xDEADC357

// ServerCertificate represents a sealed sender server certificate.
type ServerCertificate struct {
	serialized  []byte
	certificate []byte
	signature   []byte
	keyID       uint32
	publicKey   [32]byte
}

// ParseServerCertificate parses a ServerCertificate from wire bytes.
func ParseServerCertificate(data []byte) (*ServerCertificate, error) {
	certificate, signature, err := decodeServerCertificate(data)
	if err != nil {
		return nil, err
	}

	keyID, publicKey, err := decodeServerCertificateBody(certificate)
	if err != nil {
		return nil, err
	}

	return &ServerCertificate{
		serialized:  append([]byte(nil), data...),
		certificate: certificate,
		signature:   signature,
		keyID:       keyID,
		publicKey:   publicKey,
	}, nil
}

// NewServerCertificate constructs and signs a server certificate using a trust root private key.
func NewServerCertificate(keyID uint32, publicKey [32]byte, trustRootPrivate [32]byte) (*ServerCertificate, error) {
	if err := signalcrypto.ValidatePublicKey(publicKey); err != nil {
		return nil, fmt.Errorf("%w: invalid server public key", signalerrors.ErrInvalidKey)
	}

	certificate := encodeServerCertificateBody(keyID, publicKey)
	signature, err := signalcrypto.XEdDSASign(trustRootPrivate, certificate)
	if err != nil {
		return nil, fmt.Errorf("sign server certificate: %w", err)
	}
	serialized := encodeServerCertificate(certificate, signature)

	return &ServerCertificate{
		serialized:  serialized,
		certificate: certificate,
		signature:   signature,
		keyID:       keyID,
		publicKey:   publicKey,
	}, nil
}

// Serialize returns the wire encoding of the server certificate.
func (c *ServerCertificate) Serialize() []byte {
	if c == nil {
		return nil
	}
	return append([]byte(nil), c.serialized...)
}

// KeyID returns the server certificate ID.
func (c *ServerCertificate) KeyID() uint32 {
	if c == nil {
		return 0
	}
	return c.keyID
}

// PublicKey returns the server certificate public key.
func (c *ServerCertificate) PublicKey() [32]byte {
	if c == nil {
		return [32]byte{}
	}
	return c.publicKey
}

// Validate checks the server certificate signature against the trust root public key.
func (c *ServerCertificate) Validate(trustRoot [32]byte) bool {
	if c == nil {
		return false
	}
	if c.keyID == revokedServerCertificateID {
		return false
	}
	return signalcrypto.XEdDSAVerify(trustRoot, c.signature, c.certificate)
}

// ServerCertificateResolver resolves referenced server certificates by ID.
type ServerCertificateResolver interface {
	LookupServerCertificate(id uint32) (*ServerCertificate, bool)
}

// ServerCertificateMap resolves server certificates from a map.
type ServerCertificateMap map[uint32]*ServerCertificate

// LookupServerCertificate returns the server certificate for the given ID.
func (m ServerCertificateMap) LookupServerCertificate(id uint32) (*ServerCertificate, bool) {
	cert, ok := m[id]
	return cert, ok
}

// SenderCertificateParams describes a SenderCertificate to be signed.
type SenderCertificateParams struct {
	SenderUUID      string
	SenderUUIDBytes []byte
	SenderE164      string
	SenderDevice    uint32
	ExpiresAt       time.Time
	IdentityKey     [32]byte
	Signer          *ServerCertificate
	SignerID        *uint32
	SignerPrivate   [32]byte
}

// SenderCertificate represents a sealed sender sender certificate.
type SenderCertificate struct {
	serialized        []byte
	certificate       []byte
	signature         []byte
	signer            *ServerCertificate
	signerID          *uint32
	senderUUID        string
	senderUUIDBytes   []byte
	senderUUIDIsBytes bool
	senderE164        string
	hasSenderE164     bool
	senderDevice      uint32
	expiresMillis     uint64
	identityKey       [32]byte
	identityKeyBytes  []byte
}

// ParseSenderCertificate parses a SenderCertificate from wire bytes.
func ParseSenderCertificate(data []byte) (*SenderCertificate, error) {
	certificate, signature, err := decodeSenderCertificate(data)
	if err != nil {
		return nil, err
	}

	parsed, err := decodeSenderCertificateBody(certificate)
	if err != nil {
		return nil, err
	}

	return &SenderCertificate{
		serialized:        append([]byte(nil), data...),
		certificate:       certificate,
		signature:         signature,
		signer:            parsed.signer,
		signerID:          parsed.signerID,
		senderUUID:        parsed.senderUUID,
		senderUUIDBytes:   parsed.senderUUIDBytes,
		senderUUIDIsBytes: parsed.senderUUIDIsBytes,
		senderE164:        parsed.senderE164,
		hasSenderE164:     parsed.hasSenderE164,
		senderDevice:      parsed.senderDevice,
		expiresMillis:     parsed.expiresMillis,
		identityKey:       parsed.identityKey,
		identityKeyBytes:  parsed.identityKeyBytes,
	}, nil
}

// NewSenderCertificate constructs and signs a sender certificate.
func NewSenderCertificate(params SenderCertificateParams) (*SenderCertificate, error) {
	if params.SenderUUID == "" && len(params.SenderUUIDBytes) == 0 {
		return nil, fmt.Errorf("%w: sender uuid required", signalerrors.ErrInvalidMessage)
	}
	if params.SenderUUID != "" && len(params.SenderUUIDBytes) != 0 {
		return nil, fmt.Errorf("%w: sender uuid ambiguous", signalerrors.ErrInvalidMessage)
	}
	if params.Signer == nil && params.SignerID == nil {
		return nil, fmt.Errorf("%w: signer required", signalerrors.ErrInvalidMessage)
	}
	if params.Signer != nil && params.SignerID != nil {
		return nil, fmt.Errorf("%w: signer ambiguous", signalerrors.ErrInvalidMessage)
	}
	if params.ExpiresAt.IsZero() {
		return nil, fmt.Errorf("%w: expires required", signalerrors.ErrInvalidMessage)
	}
	if err := signalcrypto.ValidatePublicKey(params.IdentityKey); err != nil {
		return nil, fmt.Errorf("%w: sender identity key invalid", signalerrors.ErrInvalidKey)
	}

	if len(params.SenderUUIDBytes) > 0 && len(params.SenderUUIDBytes) != 16 {
		return nil, fmt.Errorf("%w: sender uuid bytes length %d", signalerrors.ErrInvalidMessage, len(params.SenderUUIDBytes))
	}

	expiresMillis := uint64(params.ExpiresAt.UnixMilli())
	identityKeyBytes := keys.SerializeWirePublicKey(params.IdentityKey)

	certificate := encodeSenderCertificateBody(senderCertificateBodyParams{
		senderUUID:        params.SenderUUID,
		senderUUIDBytes:   params.SenderUUIDBytes,
		senderUUIDIsBytes: len(params.SenderUUIDBytes) > 0,
		senderE164:        params.SenderE164,
		hasSenderE164:     params.SenderE164 != "",
		senderDevice:      params.SenderDevice,
		expiresMillis:     expiresMillis,
		identityKeyBytes:  identityKeyBytes,
		signer:            params.Signer,
		signerID:          params.SignerID,
	})

	signature, err := signalcrypto.XEdDSASign(params.SignerPrivate, certificate)
	if err != nil {
		return nil, fmt.Errorf("sign sender certificate: %w", err)
	}

	serialized := encodeSenderCertificate(certificate, signature)

	senderUUID := params.SenderUUID
	if senderUUID == "" {
		senderUUID, err = uuidBytesToString(params.SenderUUIDBytes)
		if err != nil {
			return nil, err
		}
	}

	return &SenderCertificate{
		serialized:        serialized,
		certificate:       certificate,
		signature:         signature,
		signer:            params.Signer,
		signerID:          params.SignerID,
		senderUUID:        senderUUID,
		senderUUIDBytes:   append([]byte(nil), params.SenderUUIDBytes...),
		senderUUIDIsBytes: len(params.SenderUUIDBytes) > 0,
		senderE164:        params.SenderE164,
		hasSenderE164:     params.SenderE164 != "",
		senderDevice:      params.SenderDevice,
		expiresMillis:     expiresMillis,
		identityKey:       params.IdentityKey,
		identityKeyBytes:  identityKeyBytes,
	}, nil
}

// Serialize returns the wire encoding of the sender certificate.
func (c *SenderCertificate) Serialize() []byte {
	if c == nil {
		return nil
	}
	return append([]byte(nil), c.serialized...)
}

// SenderUUID returns the sender UUID string.
func (c *SenderCertificate) SenderUUID() string {
	if c == nil {
		return ""
	}
	return c.senderUUID
}

// SenderE164 returns the sender E164 value, if present.
func (c *SenderCertificate) SenderE164() (string, bool) {
	if c == nil || !c.hasSenderE164 {
		return "", false
	}
	return c.senderE164, true
}

// SenderDevice returns the sender device ID.
func (c *SenderCertificate) SenderDevice() uint32 {
	if c == nil {
		return 0
	}
	return c.senderDevice
}

// ExpiresAt returns the expiration time for the sender certificate.
func (c *SenderCertificate) ExpiresAt() time.Time {
	if c == nil {
		return time.UnixMilli(0)
	}
	return time.UnixMilli(int64(c.expiresMillis))
}

// ExpiresMillis returns the expiration time as milliseconds since epoch.
func (c *SenderCertificate) ExpiresMillis() uint64 {
	if c == nil {
		return 0
	}
	return c.expiresMillis
}

// IdentityKey returns the sender's Curve25519 identity key.
func (c *SenderCertificate) IdentityKey() [32]byte {
	if c == nil {
		return [32]byte{}
	}
	return c.identityKey
}

// IdentityKeyBytes returns the wire-serialized identity key.
func (c *SenderCertificate) IdentityKeyBytes() []byte {
	if c == nil {
		return nil
	}
	return append([]byte(nil), c.identityKeyBytes...)
}

// Signer returns the embedded server certificate, if present.
func (c *SenderCertificate) Signer() (*ServerCertificate, bool) {
	if c == nil || c.signer == nil {
		return nil, false
	}
	return c.signer, true
}

// SignerID returns the referenced server certificate ID, if present.
func (c *SenderCertificate) SignerID() (uint32, bool) {
	if c == nil || c.signerID == nil {
		return 0, false
	}
	return *c.signerID, true
}

// Validate verifies the sender certificate against the provided trust roots.
func (c *SenderCertificate) Validate(trustRoots [][32]byte, validationTime time.Time, resolver ServerCertificateResolver) (bool, error) {
	if c == nil {
		return false, fmt.Errorf("%w: sender certificate is nil", signalerrors.ErrInvalidMessage)
	}
	if len(trustRoots) == 0 {
		return false, fmt.Errorf("%w: trust roots required", signalerrors.ErrInvalidKey)
	}

	signer, err := c.resolveSigner(resolver)
	if err != nil {
		return false, err
	}

	validSigner := false
	for _, root := range trustRoots {
		if signer.Validate(root) {
			validSigner = true
			break
		}
	}
	if !validSigner {
		return false, nil
	}

	if !signalcrypto.XEdDSAVerify(signer.publicKey, c.signature, c.certificate) {
		return false, nil
	}

	if validationTime.UnixMilli() > int64(c.expiresMillis) {
		return false, nil
	}

	return true, nil
}

func (c *SenderCertificate) resolveSigner(resolver ServerCertificateResolver) (*ServerCertificate, error) {
	if c.signer != nil {
		return c.signer, nil
	}
	if c.signerID == nil {
		return nil, fmt.Errorf("%w: missing signer", signalerrors.ErrInvalidMessage)
	}
	if resolver == nil {
		return nil, fmt.Errorf("%w: missing server certificate resolver", signalerrors.ErrInvalidMessage)
	}
	cert, ok := resolver.LookupServerCertificate(*c.signerID)
	if !ok || cert == nil {
		return nil, fmt.Errorf("%w: unknown server certificate id %d", signalerrors.ErrInvalidMessage, *c.signerID)
	}
	return cert, nil
}

type senderCertificateBodyParams struct {
	senderUUID        string
	senderUUIDBytes   []byte
	senderUUIDIsBytes bool
	senderE164        string
	hasSenderE164     bool
	senderDevice      uint32
	expiresMillis     uint64
	identityKeyBytes  []byte
	signer            *ServerCertificate
	signerID          *uint32
}

type senderCertificateBody struct {
	signer            *ServerCertificate
	signerID          *uint32
	senderUUID        string
	senderUUIDBytes   []byte
	senderUUIDIsBytes bool
	senderE164        string
	hasSenderE164     bool
	senderDevice      uint32
	expiresMillis     uint64
	identityKey       [32]byte
	identityKeyBytes  []byte
}

func encodeServerCertificate(certificate, signature []byte) []byte {
	out := make([]byte, 0, 64+len(certificate)+len(signature))
	out = protowire.AppendTag(out, 1, protowire.BytesType)
	out = protowire.AppendBytes(out, certificate)
	out = protowire.AppendTag(out, 2, protowire.BytesType)
	out = protowire.AppendBytes(out, signature)
	return out
}

func decodeServerCertificate(data []byte) ([]byte, []byte, error) {
	if len(data) == 0 {
		return nil, nil, fmt.Errorf("%w: server certificate empty", signalerrors.ErrInvalidMessage)
	}
	var certificate []byte
	var signature []byte

	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return nil, nil, fmt.Errorf("%w: server certificate tag", signalerrors.ErrInvalidMessage)
		}
		data = data[n:]
		switch num {
		case 1: // certificate
			if typ != protowire.BytesType {
				return nil, nil, fmt.Errorf("%w: server certificate type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, nil, fmt.Errorf("%w: server certificate bytes", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
			certificate = append([]byte(nil), val...)
		case 2: // signature
			if typ != protowire.BytesType {
				return nil, nil, fmt.Errorf("%w: server signature type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, nil, fmt.Errorf("%w: server signature bytes", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
			signature = append([]byte(nil), val...)
		default:
			n := protowire.ConsumeFieldValue(num, typ, data)
			if n < 0 {
				return nil, nil, fmt.Errorf("%w: server certificate field", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
		}
	}

	if certificate == nil || signature == nil {
		return nil, nil, fmt.Errorf("%w: server certificate missing fields", signalerrors.ErrInvalidMessage)
	}
	return certificate, signature, nil
}

func encodeServerCertificateBody(keyID uint32, publicKey [32]byte) []byte {
	out := make([]byte, 0, 48)
	out = protowire.AppendTag(out, 1, protowire.VarintType)
	out = protowire.AppendVarint(out, uint64(keyID))
	out = protowire.AppendTag(out, 2, protowire.BytesType)
	out = protowire.AppendBytes(out, keys.SerializeWirePublicKey(publicKey))
	return out
}

func decodeServerCertificateBody(data []byte) (uint32, [32]byte, error) {
	var keyID uint32
	var keyBytes []byte
	var gotID bool
	var gotKey bool

	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return 0, [32]byte{}, fmt.Errorf("%w: server certificate body tag", signalerrors.ErrInvalidMessage)
		}
		data = data[n:]
		switch num {
		case 1: // id
			if typ != protowire.VarintType {
				return 0, [32]byte{}, fmt.Errorf("%w: server certificate id type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeVarint(data)
			if n < 0 || val > math.MaxUint32 {
				return 0, [32]byte{}, fmt.Errorf("%w: server certificate id", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
			keyID = uint32(val)
			gotID = true
		case 2: // key
			if typ != protowire.BytesType {
				return 0, [32]byte{}, fmt.Errorf("%w: server certificate key type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return 0, [32]byte{}, fmt.Errorf("%w: server certificate key", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
			keyBytes = append([]byte(nil), val...)
			gotKey = true
		default:
			n := protowire.ConsumeFieldValue(num, typ, data)
			if n < 0 {
				return 0, [32]byte{}, fmt.Errorf("%w: server certificate body field", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
		}
	}

	if !gotID || !gotKey {
		return 0, [32]byte{}, fmt.Errorf("%w: server certificate missing fields", signalerrors.ErrInvalidMessage)
	}

	key, err := keys.DeserializeWirePublicKey(keyBytes)
	if err != nil {
		return 0, [32]byte{}, err
	}

	return keyID, key, nil
}

func encodeSenderCertificate(certificate, signature []byte) []byte {
	out := make([]byte, 0, 64+len(certificate)+len(signature))
	out = protowire.AppendTag(out, 1, protowire.BytesType)
	out = protowire.AppendBytes(out, certificate)
	out = protowire.AppendTag(out, 2, protowire.BytesType)
	out = protowire.AppendBytes(out, signature)
	return out
}

func decodeSenderCertificate(data []byte) ([]byte, []byte, error) {
	if len(data) == 0 {
		return nil, nil, fmt.Errorf("%w: sender certificate empty", signalerrors.ErrInvalidMessage)
	}
	var certificate []byte
	var signature []byte

	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return nil, nil, fmt.Errorf("%w: sender certificate tag", signalerrors.ErrInvalidMessage)
		}
		data = data[n:]
		switch num {
		case 1: // certificate
			if typ != protowire.BytesType {
				return nil, nil, fmt.Errorf("%w: sender certificate type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, nil, fmt.Errorf("%w: sender certificate bytes", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
			certificate = append([]byte(nil), val...)
		case 2: // signature
			if typ != protowire.BytesType {
				return nil, nil, fmt.Errorf("%w: sender signature type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, nil, fmt.Errorf("%w: sender signature bytes", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
			signature = append([]byte(nil), val...)
		default:
			n := protowire.ConsumeFieldValue(num, typ, data)
			if n < 0 {
				return nil, nil, fmt.Errorf("%w: sender certificate field", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
		}
	}

	if certificate == nil || signature == nil {
		return nil, nil, fmt.Errorf("%w: sender certificate missing fields", signalerrors.ErrInvalidMessage)
	}
	return certificate, signature, nil
}

func encodeSenderCertificateBody(params senderCertificateBodyParams) []byte {
	out := make([]byte, 0, 128)
	if params.hasSenderE164 {
		out = protowire.AppendTag(out, 1, protowire.BytesType)
		out = protowire.AppendString(out, params.senderE164)
	}
	if params.senderUUIDIsBytes {
		out = protowire.AppendTag(out, 7, protowire.BytesType)
		out = protowire.AppendBytes(out, params.senderUUIDBytes)
	} else {
		out = protowire.AppendTag(out, 6, protowire.BytesType)
		out = protowire.AppendString(out, params.senderUUID)
	}
	out = protowire.AppendTag(out, 2, protowire.VarintType)
	out = protowire.AppendVarint(out, uint64(params.senderDevice))
	out = protowire.AppendTag(out, 3, protowire.Fixed64Type)
	out = protowire.AppendFixed64(out, params.expiresMillis)
	out = protowire.AppendTag(out, 4, protowire.BytesType)
	out = protowire.AppendBytes(out, params.identityKeyBytes)
	if params.signer != nil {
		out = protowire.AppendTag(out, 5, protowire.BytesType)
		out = protowire.AppendBytes(out, params.signer.Serialize())
	} else if params.signerID != nil {
		out = protowire.AppendTag(out, 8, protowire.VarintType)
		out = protowire.AppendVarint(out, uint64(*params.signerID))
	}
	return out
}

func decodeSenderCertificateBody(data []byte) (*senderCertificateBody, error) {
	var (
		senderUUID        string
		senderUUIDBytes   []byte
		senderUUIDIsBytes bool
		senderE164        string
		hasSenderE164     bool
		senderDevice      uint32
		expiresMillis     uint64
		identityKeyBytes  []byte
		signer            *ServerCertificate
		signerID          *uint32
		gotDevice         bool
		gotExpires        bool
		gotIdentity       bool
		gotUUID           bool
		gotSigner         bool
	)

	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return nil, fmt.Errorf("%w: sender certificate body tag", signalerrors.ErrInvalidMessage)
		}
		data = data[n:]
		switch num {
		case 1: // sender_e164
			if typ != protowire.BytesType {
				return nil, fmt.Errorf("%w: sender e164 type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, fmt.Errorf("%w: sender e164", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
			senderE164 = string(val)
			hasSenderE164 = true
		case 6: // uuid_string
			if typ != protowire.BytesType {
				return nil, fmt.Errorf("%w: sender uuid type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, fmt.Errorf("%w: sender uuid string", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
			if gotUUID {
				return nil, fmt.Errorf("%w: duplicate sender uuid", signalerrors.ErrInvalidMessage)
			}
			senderUUID = string(val)
			senderUUIDIsBytes = false
			gotUUID = true
		case 7: // uuid_bytes
			if typ != protowire.BytesType {
				return nil, fmt.Errorf("%w: sender uuid bytes type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, fmt.Errorf("%w: sender uuid bytes", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
			if gotUUID {
				return nil, fmt.Errorf("%w: duplicate sender uuid", signalerrors.ErrInvalidMessage)
			}
			if len(val) != 16 {
				return nil, fmt.Errorf("%w: sender uuid bytes length %d", signalerrors.ErrInvalidMessage, len(val))
			}
			senderUUIDBytes = append([]byte(nil), val...)
			senderUUIDIsBytes = true
			parsedUUID, err := uuidBytesToString(val)
			if err != nil {
				return nil, err
			}
			senderUUID = parsedUUID
			gotUUID = true
		case 2: // sender_device
			if typ != protowire.VarintType {
				return nil, fmt.Errorf("%w: sender device type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeVarint(data)
			if n < 0 || val > math.MaxUint32 {
				return nil, fmt.Errorf("%w: sender device", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
			senderDevice = uint32(val)
			gotDevice = true
		case 3: // expires
			if typ != protowire.Fixed64Type {
				return nil, fmt.Errorf("%w: sender expires type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeFixed64(data)
			if n < 0 {
				return nil, fmt.Errorf("%w: sender expires", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
			expiresMillis = val
			gotExpires = true
		case 4: // identity_key
			if typ != protowire.BytesType {
				return nil, fmt.Errorf("%w: sender identity key type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, fmt.Errorf("%w: sender identity key", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
			identityKeyBytes = append([]byte(nil), val...)
			gotIdentity = true
		case 5: // signer certificate
			if typ != protowire.BytesType {
				return nil, fmt.Errorf("%w: signer certificate type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, fmt.Errorf("%w: signer certificate", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
			if gotSigner {
				return nil, fmt.Errorf("%w: duplicate signer", signalerrors.ErrInvalidMessage)
			}
			parsedSigner, err := ParseServerCertificate(val)
			if err != nil {
				return nil, err
			}
			signer = parsedSigner
			gotSigner = true
		case 8: // signer id
			if typ != protowire.VarintType {
				return nil, fmt.Errorf("%w: signer id type", signalerrors.ErrInvalidMessage)
			}
			val, n := protowire.ConsumeVarint(data)
			if n < 0 || val > math.MaxUint32 {
				return nil, fmt.Errorf("%w: signer id", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
			if gotSigner {
				return nil, fmt.Errorf("%w: duplicate signer", signalerrors.ErrInvalidMessage)
			}
			id := uint32(val)
			signerID = &id
			gotSigner = true
		default:
			n := protowire.ConsumeFieldValue(num, typ, data)
			if n < 0 {
				return nil, fmt.Errorf("%w: sender certificate body field", signalerrors.ErrInvalidMessage)
			}
			data = data[n:]
		}
	}

	if !gotDevice || !gotExpires || !gotIdentity || !gotUUID || !gotSigner {
		return nil, fmt.Errorf("%w: sender certificate missing fields", signalerrors.ErrInvalidMessage)
	}

	identityKey, err := keys.DeserializeWirePublicKey(identityKeyBytes)
	if err != nil {
		return nil, err
	}

	return &senderCertificateBody{
		signer:            signer,
		signerID:          signerID,
		senderUUID:        senderUUID,
		senderUUIDBytes:   senderUUIDBytes,
		senderUUIDIsBytes: senderUUIDIsBytes,
		senderE164:        senderE164,
		hasSenderE164:     hasSenderE164,
		senderDevice:      senderDevice,
		expiresMillis:     expiresMillis,
		identityKey:       identityKey,
		identityKeyBytes:  identityKeyBytes,
	}, nil
}

func uuidBytesToString(raw []byte) (string, error) {
	if len(raw) != 16 {
		return "", fmt.Errorf("%w: uuid bytes length %d", signalerrors.ErrInvalidMessage, len(raw))
	}
	var out [36]byte
	hex.Encode(out[0:8], raw[0:4])
	out[8] = '-'
	hex.Encode(out[9:13], raw[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], raw[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], raw[8:10])
	out[23] = '-'
	hex.Encode(out[24:36], raw[10:16])
	return string(out[:]), nil
}

func compareIdentityKeyBytes(a []byte, b [32]byte) bool {
	wire := keys.SerializeWirePublicKey(b)
	if len(a) != len(wire) {
		return false
	}
	return subtle.ConstantTimeCompare(a, wire) == 1
}
