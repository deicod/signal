package crypto

import (
	"fmt"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
)

const kyber1024KeyType byte = 0x08

// KyberKeyPair holds serialized Kyber1024 keys (type prefix + raw key bytes).
type KyberKeyPair struct {
	PublicKey  []byte
	PrivateKey []byte
}

// GenerateKyber1024KeyPair creates a Kyber1024 key pair serialized with type prefixes.
func GenerateKyber1024KeyPair() (*KyberKeyPair, error) {
	pk, sk, err := kyber1024.GenerateKeyPair(nil)
	if err != nil {
		return nil, fmt.Errorf("kyber1024: generate keypair: %w", err)
	}
	pkRaw, err := pk.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("kyber1024: marshal public key: %w", err)
	}
	skRaw, err := sk.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("kyber1024: marshal private key: %w", err)
	}
	return &KyberKeyPair{
		PublicKey:  append([]byte{kyber1024KeyType}, pkRaw...),
		PrivateKey: append([]byte{kyber1024KeyType}, skRaw...),
	}, nil
}

// Kyber1024Encapsulate encapsulates a shared secret to the serialized public key.
func Kyber1024Encapsulate(publicKey []byte) ([]byte, []byte, error) {
	pk, err := unmarshalKyberPublicKey(publicKey)
	if err != nil {
		return nil, nil, err
	}
	ct, ss, err := kyberScheme().Encapsulate(pk)
	if err != nil {
		return nil, nil, fmt.Errorf("kyber1024: encapsulate: %w", err)
	}
	ciphertext := append([]byte{kyber1024KeyType}, ct...)
	sharedSecret := append([]byte(nil), ss...)
	return sharedSecret, ciphertext, nil
}

// Kyber1024Decapsulate decapsulates a shared secret from the serialized private key and ciphertext.
func Kyber1024Decapsulate(privateKey []byte, ciphertext []byte) ([]byte, error) {
	sk, err := unmarshalKyberPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	rawCT, err := unmarshalKyberCiphertext(ciphertext)
	if err != nil {
		return nil, err
	}
	ss, err := kyberScheme().Decapsulate(sk, rawCT)
	if err != nil {
		return nil, fmt.Errorf("kyber1024: decapsulate: %w", err)
	}
	return append([]byte(nil), ss...), nil
}

// IsKyber1024PublicKey returns true if the serialized public key matches Kyber1024 sizing.
func IsKyber1024PublicKey(data []byte) bool {
	return len(data) == 1+kyber1024.PublicKeySize && len(data) > 0 && data[0] == kyber1024KeyType
}

func kyberScheme() kem.Scheme {
	return kyber1024.Scheme()
}

func unmarshalKyberPublicKey(data []byte) (kem.PublicKey, error) {
	if len(data) != 1+kyber1024.PublicKeySize {
		return nil, fmt.Errorf("kyber1024: public key length %d", len(data))
	}
	if data[0] != kyber1024KeyType {
		return nil, fmt.Errorf("kyber1024: unsupported key type 0x%02x", data[0])
	}
	pk, err := kyberScheme().UnmarshalBinaryPublicKey(data[1:])
	if err != nil {
		return nil, fmt.Errorf("kyber1024: parse public key: %w", err)
	}
	return pk, nil
}

func unmarshalKyberPrivateKey(data []byte) (kem.PrivateKey, error) {
	if len(data) != 1+kyber1024.PrivateKeySize {
		return nil, fmt.Errorf("kyber1024: private key length %d", len(data))
	}
	if data[0] != kyber1024KeyType {
		return nil, fmt.Errorf("kyber1024: unsupported key type 0x%02x", data[0])
	}
	sk, err := kyberScheme().UnmarshalBinaryPrivateKey(data[1:])
	if err != nil {
		return nil, fmt.Errorf("kyber1024: parse private key: %w", err)
	}
	return sk, nil
}

func unmarshalKyberCiphertext(data []byte) ([]byte, error) {
	if len(data) != 1+kyber1024.CiphertextSize {
		return nil, fmt.Errorf("kyber1024: ciphertext length %d", len(data))
	}
	if data[0] != kyber1024KeyType {
		return nil, fmt.Errorf("kyber1024: unsupported ciphertext type 0x%02x", data[0])
	}
	return data[1:], nil
}
