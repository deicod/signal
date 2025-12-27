package spqr

import (
	"fmt"

	signalcrypto "github.com/deicod/signal/crypto"
)

var (
	pqrSckaKeyInfo = []byte("Signal_PQCKA_V1_MLKEM768:SCKA Key")
)

type epochSecret struct {
	epoch  uint64
	secret []byte
}

func deriveSckaKey(epoch uint64, secret []byte) ([]byte, error) {
	info := make([]byte, 0, len(pqrSckaKeyInfo)+8)
	info = append(info, pqrSckaKeyInfo...)
	info = append(info, epochBytes(epoch)...)
	return signalcrypto.HKDF(secret, make([]byte, 32), info, 32)
}

// Unchunked send_ek path.
type unchunkedKeysUnsampled struct {
	epoch uint64
	auth  *authenticator
}

type unchunkedHeaderSent struct {
	epoch uint64
	auth  *authenticator
	ek    []byte
	dk    []byte
}

type unchunkedEkSent struct {
	epoch uint64
	auth  *authenticator
	dk    []byte
}

type unchunkedEkSentCt1Received struct {
	epoch uint64
	auth  *authenticator
	dk    []byte
	ct1   []byte
}

func newUnchunkedKeysUnsampled(authKey []byte) (*unchunkedKeysUnsampled, error) {
	if len(authKey) == 0 {
		return nil, ErrInvalidMessage
	}
	return &unchunkedKeysUnsampled{
		epoch: 1,
		auth:  newAuthenticator(authKey, 1),
	}, nil
}

func (s *unchunkedKeysUnsampled) sendHeader() (*unchunkedHeaderSent, []byte, []byte, error) {
	keys, err := mlkemGenerateKeys()
	if err != nil {
		return nil, nil, nil, err
	}
	mac := s.auth.macHdr(s.epoch, keys.hdr)
	next := &unchunkedHeaderSent{
		epoch: s.epoch,
		auth:  s.auth,
		ek:    keys.ek,
		dk:    keys.dk,
	}
	return next, keys.hdr, mac, nil
}

func (s *unchunkedHeaderSent) sendEk() (*unchunkedEkSent, []byte) {
	return &unchunkedEkSent{
		epoch: s.epoch,
		auth:  s.auth,
		dk:    s.dk,
	}, append([]byte(nil), s.ek...)
}

func (s *unchunkedEkSent) recvCt1(epoch uint64, ct1 []byte) *unchunkedEkSentCt1Received {
	if epoch != s.epoch {
		return &unchunkedEkSentCt1Received{epoch: s.epoch, auth: s.auth, dk: s.dk, ct1: append([]byte(nil), ct1...)}
	}
	return &unchunkedEkSentCt1Received{
		epoch: s.epoch,
		auth:  s.auth,
		dk:    s.dk,
		ct1:   append([]byte(nil), ct1...),
	}
}

func (s *unchunkedEkSentCt1Received) recvCt2(ct2 []byte, mac []byte) (*unchunkedNoHeaderReceived, *epochSecret, error) {
	if len(ct2) != mlkemCiphertext2Size {
		return nil, nil, fmt.Errorf("spqr: invalid ct2 size %d", len(ct2))
	}
	if len(mac) != authenticatorMacSize {
		return nil, nil, ErrInvalidMessage
	}
	ss, err := mlkemDecaps(s.dk, s.ct1, ct2)
	if err != nil {
		return nil, nil, err
	}
	key, err := deriveSckaKey(s.epoch, ss)
	signalcrypto.ZeroBytes(ss)
	if err != nil {
		return nil, nil, err
	}
	if err := s.auth.update(s.epoch, key); err != nil {
		return nil, nil, err
	}
	fullCt := append(append([]byte(nil), s.ct1...), ct2...)
	if err := s.auth.verifyCt(s.epoch, fullCt, mac); err != nil {
		return nil, nil, err
	}
	next := &unchunkedNoHeaderReceived{
		epoch: s.epoch + 1,
		auth:  s.auth,
	}
	return next, &epochSecret{epoch: s.epoch, secret: key}, nil
}

// Unchunked send_ct path.
type unchunkedNoHeaderReceived struct {
	epoch uint64
	auth  *authenticator
}

type unchunkedHeaderReceived struct {
	epoch uint64
	auth  *authenticator
	hdr   []byte
}

type unchunkedCt1Sent struct {
	epoch  uint64
	auth   *authenticator
	hdr    []byte
	encaps mlkemEncapsulationState
	ct1    []byte
}

type unchunkedCt1SentEkReceived struct {
	epoch  uint64
	auth   *authenticator
	encaps mlkemEncapsulationState
	ek     []byte
	ct1    []byte
}

type unchunkedCt2Sent struct {
	epoch uint64
	auth  *authenticator
}

func newUnchunkedNoHeaderReceived(authKey []byte) (*unchunkedNoHeaderReceived, error) {
	if len(authKey) == 0 {
		return nil, ErrInvalidMessage
	}
	return &unchunkedNoHeaderReceived{
		epoch: 1,
		auth:  newAuthenticator(authKey, 1),
	}, nil
}

func (s *unchunkedNoHeaderReceived) recvHeader(epoch uint64, hdr []byte, mac []byte) (*unchunkedHeaderReceived, error) {
	if epoch != s.epoch {
		return nil, ErrEpochOutOfRange
	}
	if len(hdr) != mlkemHeaderSize {
		return nil, ErrInvalidMessage
	}
	if err := s.auth.verifyHdr(epoch, hdr, mac); err != nil {
		return nil, err
	}
	return &unchunkedHeaderReceived{
		epoch: s.epoch,
		auth:  s.auth,
		hdr:   append([]byte(nil), hdr...),
	}, nil
}

func (s *unchunkedHeaderReceived) sendCt1() (*unchunkedCt1Sent, []byte, *epochSecret, error) {
	ct1, encapsState, ss, err := mlkemEncaps1(s.hdr)
	if err != nil {
		return nil, nil, nil, err
	}
	key, err := deriveSckaKey(s.epoch, ss)
	signalcrypto.ZeroBytes(ss)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := s.auth.update(s.epoch, key); err != nil {
		return nil, nil, nil, err
	}
	next := &unchunkedCt1Sent{
		epoch:  s.epoch,
		auth:   s.auth,
		hdr:    append([]byte(nil), s.hdr...),
		encaps: encapsState,
		ct1:    append([]byte(nil), ct1...),
	}
	return next, ct1, &epochSecret{epoch: s.epoch, secret: key}, nil
}

func (s *unchunkedCt1Sent) recvEk(epoch uint64, ek []byte) (*unchunkedCt1SentEkReceived, error) {
	if epoch != s.epoch {
		return nil, ErrEpochOutOfRange
	}
	if !mlkemEKMatchesHeader(ek, s.hdr) {
		return nil, ErrErroneousData
	}
	return &unchunkedCt1SentEkReceived{
		epoch:  s.epoch,
		auth:   s.auth,
		encaps: s.encaps,
		ek:     append([]byte(nil), ek...),
		ct1:    append([]byte(nil), s.ct1...),
	}, nil
}

func (s *unchunkedCt1SentEkReceived) sendCt2() (*unchunkedCt2Sent, []byte, []byte, error) {
	ct2, err := mlkemEncaps2(s.ek, s.encaps)
	if err != nil {
		return nil, nil, nil, err
	}
	fullCt := append(append([]byte(nil), s.ct1...), ct2...)
	mac := s.auth.macCt(s.epoch, fullCt)
	next := &unchunkedCt2Sent{epoch: s.epoch, auth: s.auth}
	return next, ct2, mac, nil
}

func (s *unchunkedCt2Sent) recvNextEpoch(nextEpoch uint64) (*unchunkedKeysUnsampled, error) {
	if nextEpoch != s.epoch+1 {
		return nil, ErrEpochOutOfRange
	}
	return &unchunkedKeysUnsampled{
		epoch: s.epoch + 1,
		auth:  s.auth,
	}, nil
}
