package ratchet

import "fmt"

// MaxSkip defines the maximum number of skipped message keys to retain to
// mitigate unbounded memory growth.
const MaxSkip = 1000

// skipMessageKeys stores message keys for skipped message numbers up to (but not including) until.
func (s *State) skipMessageKeys(until uint32) error {
	for s.Nr < until {
		if len(s.MKSkipped) >= MaxSkip {
			return fmt.Errorf("ratchet: max skipped message keys exceeded")
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

// trySkippedMessageKey returns a skipped message key if present for the given header.
func (s *State) trySkippedMessageKey(header *Header) (*[32]byte, bool) {
	if header == nil {
		return nil, false
	}
	key := SkippedKey{PublicKey: header.DH, N: header.N}
	mk, ok := s.MKSkipped[key]
	if !ok {
		return nil, false
	}
	delete(s.MKSkipped, key)
	return &mk, true
}

// cleanupSkippedKeys drops skipped keys that belong to older DH ratchets to prevent unbounded growth.
func (s *State) cleanupSkippedKeys(currentDH [32]byte) {
	for k := range s.MKSkipped {
		if k.PublicKey != currentDH {
			delete(s.MKSkipped, k)
		}
	}
}
