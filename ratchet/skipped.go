package ratchet

import (
	"fmt"
	"math"

	signalerrors "github.com/deicod/signal/errors"
)

// MaxSkip defines the maximum number of skipped message keys to retain to
// mitigate unbounded memory growth.
const MaxSkip = 1000

// skipMessageKeys stores message keys for skipped message numbers up to (but not including) until.
func (s *State) skipMessageKeys(until uint32) error {
	for s.Nr < until {
		if s.Nr == math.MaxUint32 {
			return fmt.Errorf("%w: receive counter overflow", signalerrors.ErrCounterOverflow)
		}
		if len(s.MKSkipped) >= MaxSkip {
			return fmt.Errorf("%w: ratchet max skipped message keys exceeded", signalerrors.ErrMaxSkipExceeded)
		}
		if s.DHr == nil {
			return fmt.Errorf("ratchet: missing DHr while skipping")
		}
		newCKr, mk := KDFChain(s.CKr)
		s.CKr = newCKr
		key := SkippedKey{
			PublicKey: *s.DHr,
			N:         s.Nr,
		}
		s.MKSkipped[key] = mk
		s.Nr++
	}
	return nil
}

func skippedKeyForHeader(header *Header) (SkippedKey, bool) {
	if header == nil {
		return SkippedKey{}, false
	}
	return SkippedKey{PublicKey: header.DH, N: header.N}, true
}

// cleanupSkippedKeys drops skipped keys that belong to older DH ratchets to prevent unbounded growth.
func (s *State) cleanupSkippedKeys(currentDH [32]byte) {
	for k := range s.MKSkipped {
		if k.PublicKey != currentDH {
			delete(s.MKSkipped, k)
		}
	}
}
