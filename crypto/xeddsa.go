package crypto

import (
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"fmt"
	"io"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
)

var xeddsaHashPrefix = [32]byte{
	0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
}

// XEdDSASign returns an XEdDSA signature over the provided message pieces.
func XEdDSASign(privateKey [32]byte, messagePieces ...[]byte) ([]byte, error) {
	return xeddsaSign(rand.Reader, privateKey, messagePieces...)
}

// XEdDSAVerify validates an XEdDSA signature over the provided message pieces.
func XEdDSAVerify(publicKey [32]byte, signature []byte, messagePieces ...[]byte) bool {
	if len(signature) != 64 {
		return false
	}

	var sig [64]byte
	copy(sig[:], signature)
	signBit := (sig[63] & 0x80) >> 7

	edPub, ok := montgomeryToEdwards(publicKey, signBit)
	if !ok {
		return false
	}
	edPubBytes := edPub.Bytes()

	var capR [32]byte
	copy(capR[:], sig[:32])

	var sBytes [32]byte
	copy(sBytes[:], sig[32:])
	sBytes[31] &= 0x7f
	if (sBytes[31] & 0xe0) != 0 {
		return false
	}

	s, err := scalarFromBytesModOrder(sBytes)
	if err != nil {
		return false
	}

	hash := sha512.New()
	hash.Write(capR[:])
	hash.Write(edPubBytes)
	for _, piece := range messagePieces {
		hash.Write(piece)
	}
	h, err := scalarFromHash(hash.Sum(nil))
	if err != nil {
		return false
	}

	minusA := new(edwards25519.Point).Negate(edPub)
	capRCheck := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(h, minusA, s)
	return subtle.ConstantTimeCompare(capRCheck.Bytes(), capR[:]) == 1
}

// XEdDSASigningPublicKey derives the Ed25519-style public key used to compute the sign bit.
func XEdDSASigningPublicKey(privateKey [32]byte) ([32]byte, error) {
	var out [32]byte
	clamped := privateKey
	clampCurve25519Scalar(&clamped)
	a, err := scalarFromBytesModOrder(clamped)
	if err != nil {
		return out, err
	}
	edPub := new(edwards25519.Point).ScalarBaseMult(a)
	copy(out[:], edPub.Bytes())
	return out, nil
}

func xeddsaSign(rng io.Reader, privateKey [32]byte, messagePieces ...[]byte) ([]byte, error) {
	var randomBytes [64]byte
	if _, err := io.ReadFull(rng, randomBytes[:]); err != nil {
		return nil, fmt.Errorf("xeddsa: random: %w", err)
	}

	keyData := privateKey
	clampCurve25519Scalar(&keyData)
	a, err := scalarFromBytesModOrder(keyData)
	if err != nil {
		return nil, err
	}
	edPub := new(edwards25519.Point).ScalarBaseMult(a)
	edPubBytes := edPub.Bytes()
	signBit := edPubBytes[31] & 0x80

	hash1 := sha512.New()
	hash1.Write(xeddsaHashPrefix[:])
	hash1.Write(keyData[:])
	for _, piece := range messagePieces {
		hash1.Write(piece)
	}
	hash1.Write(randomBytes[:])

	r, err := scalarFromHash(hash1.Sum(nil))
	if err != nil {
		return nil, err
	}
	capR := new(edwards25519.Point).ScalarBaseMult(r)

	hash := sha512.New()
	hash.Write(capR.Bytes())
	hash.Write(edPubBytes)
	for _, piece := range messagePieces {
		hash.Write(piece)
	}
	h, err := scalarFromHash(hash.Sum(nil))
	if err != nil {
		return nil, err
	}

	s := new(edwards25519.Scalar).MultiplyAdd(h, a, r)

	sig := make([]byte, 64)
	copy(sig[:32], capR.Bytes())
	copy(sig[32:], s.Bytes())
	sig[63] &= 0x7f
	sig[63] |= signBit
	return sig, nil
}

func scalarFromBytesModOrder(in [32]byte) (*edwards25519.Scalar, error) {
	var wide [64]byte
	copy(wide[:32], in[:])
	s := edwards25519.NewScalar()
	if _, err := s.SetUniformBytes(wide[:]); err != nil {
		return nil, err
	}
	return s, nil
}

func scalarFromHash(sum []byte) (*edwards25519.Scalar, error) {
	if len(sum) != 64 {
		return nil, fmt.Errorf("xeddsa: invalid hash length %d", len(sum))
	}
	s := edwards25519.NewScalar()
	if _, err := s.SetUniformBytes(sum); err != nil {
		return nil, err
	}
	return s, nil
}

func montgomeryToEdwards(u [32]byte, signBit byte) (*edwards25519.Point, bool) {
	var uElem field.Element
	if _, err := uElem.SetBytes(u[:]); err != nil {
		return nil, false
	}

	var one field.Element
	one.One()
	var uPlusOne field.Element
	uPlusOne.Add(&uElem, &one)
	if uPlusOne.Equal(&field.Element{}) == 1 {
		return nil, false
	}

	var uMinusOne field.Element
	uMinusOne.Subtract(&uElem, &one)
	var inv field.Element
	inv.Invert(&uPlusOne)

	var y field.Element
	y.Multiply(&uMinusOne, &inv)
	yBytes := y.Bytes()
	yBytes[31] &^= 0x80
	if signBit&1 == 1 {
		yBytes[31] |= 0x80
	}

	point := new(edwards25519.Point)
	if _, err := point.SetBytes(yBytes[:]); err != nil {
		return nil, false
	}
	return point, true
}
