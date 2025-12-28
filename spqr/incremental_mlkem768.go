package spqr

import (
	"crypto/subtle"
	"fmt"

	"golang.org/x/crypto/sha3"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/pke/kyber/kyber768"
	signalcrypto "github.com/deicod/signal/crypto"
)

const (
	mlkemCiphertext1Size      = 960
	mlkemCiphertext2Size      = 128
	mlkemHeaderSize           = 64
	mlkemEncapsulationKeySize = 1152
	mlkemDecapsulationKeySize = mlkem768.PrivateKeySize
)

type mlkemEncapsulationState struct {
	seed   [32]byte
	rho    [32]byte
	pkHash [32]byte
}

type mlkemKeys struct {
	hdr []byte
	ek  []byte
	dk  []byte
}

func mlkemGenerateKeys() (*mlkemKeys, error) {
	seed, err := signalcrypto.RandomBytes(mlkem768.KeySeedSize)
	if err != nil {
		return nil, err
	}
	pk, sk := mlkem768.NewKeyFromSeed(seed)
	pkBytes := make([]byte, mlkem768.PublicKeySize)
	pk.Pack(pkBytes)

	hash := sha3.Sum256(pkBytes)

	hdr := make([]byte, mlkemHeaderSize)
	copy(hdr, pkBytes[mlkemEncapsulationKeySize:])
	copy(hdr[32:], hash[:])
	ek := append([]byte(nil), pkBytes[:mlkemEncapsulationKeySize]...)

	dk := make([]byte, mlkem768.PrivateKeySize)
	sk.Pack(dk)

	return &mlkemKeys{hdr: hdr, ek: ek, dk: dk}, nil
}

func mlkemEKMatchesHeader(ek []byte, hdr []byte) bool {
	if len(ek) != mlkemEncapsulationKeySize || len(hdr) != mlkemHeaderSize {
		return false
	}
	pkBytes := make([]byte, mlkemEncapsulationKeySize+32)
	copy(pkBytes, ek)
	copy(pkBytes[mlkemEncapsulationKeySize:], hdr[:32])
	pkHash := sha3.Sum256(pkBytes)
	if subtle.ConstantTimeCompare(pkHash[:], hdr[32:]) != 1 {
		return false
	}
	var pk kyber768.PublicKey
	if err := pk.UnpackMLKEM(pkBytes); err != nil {
		return false
	}
	return true
}

func mlkemEncaps1(hdr []byte) ([]byte, mlkemEncapsulationState, []byte, error) {
	if len(hdr) != mlkemHeaderSize {
		return nil, mlkemEncapsulationState{}, nil, fmt.Errorf("spqr: invalid mlkem header size %d", len(hdr))
	}
	seedBytes, err := signalcrypto.RandomBytes(mlkem768.EncapsulationSeedSize)
	if err != nil {
		return nil, mlkemEncapsulationState{}, nil, err
	}
	var seed [32]byte
	copy(seed[:], seedBytes)
	var rho [32]byte
	copy(rho[:], hdr[:32])
	var pkHash [32]byte
	copy(pkHash[:], hdr[32:])

	kr := sha3.Sum512(append(seed[:], pkHash[:]...))
	sharedSecret := append([]byte(nil), kr[:32]...)
	r := kr[32:]

	pkBytes := make([]byte, mlkemEncapsulationKeySize+32)
	copy(pkBytes[mlkemEncapsulationKeySize:], rho[:])
	var pk kyber768.PublicKey
	pk.Unpack(pkBytes)
	ct := make([]byte, kyber768.CiphertextSize)
	pk.EncryptTo(ct, seed[:], r)

	ct1 := append([]byte(nil), ct[:mlkemCiphertext1Size]...)
	state := mlkemEncapsulationState{seed: seed, rho: rho, pkHash: pkHash}
	return ct1, state, sharedSecret, nil
}

func mlkemEncaps2(ek []byte, state mlkemEncapsulationState) ([]byte, error) {
	if len(ek) != mlkemEncapsulationKeySize {
		return nil, fmt.Errorf("spqr: invalid mlkem ek size %d", len(ek))
	}
	pkBytes := make([]byte, mlkemEncapsulationKeySize+32)
	copy(pkBytes, ek)
	copy(pkBytes[mlkemEncapsulationKeySize:], state.rho[:])
	var pk kyber768.PublicKey
	pk.Unpack(pkBytes)
	kr := sha3.Sum512(append(state.seed[:], state.pkHash[:]...))
	r := kr[32:]
	ct := make([]byte, kyber768.CiphertextSize)
	pk.EncryptTo(ct, state.seed[:], r)
	ct2 := append([]byte(nil), ct[mlkemCiphertext1Size:]...)
	return ct2, nil
}

func mlkemDecaps(dk []byte, ct1 []byte, ct2 []byte) ([]byte, error) {
	if len(dk) != mlkem768.PrivateKeySize {
		return nil, fmt.Errorf("spqr: invalid mlkem dk size %d", len(dk))
	}
	if len(ct1) != mlkemCiphertext1Size || len(ct2) != mlkemCiphertext2Size {
		return nil, fmt.Errorf("spqr: invalid mlkem ciphertext size")
	}
	ciphertext := make([]byte, 0, kyber768.CiphertextSize)
	ciphertext = append(ciphertext, ct1...)
	ciphertext = append(ciphertext, ct2...)
	var sk mlkem768.PrivateKey
	if err := sk.Unpack(dk); err != nil {
		return nil, err
	}
	ss := make([]byte, mlkem768.SharedKeySize)
	sk.DecapsulateTo(ss, ciphertext)
	return ss, nil
}
