package spqr

import "errors"

var (
	// ErrInvalidMessage indicates a malformed SPQR message.
	ErrInvalidMessage = errors.New("spqr: invalid message")
	// ErrUnsupportedVersion indicates the SPQR version is unsupported.
	ErrUnsupportedVersion = errors.New("spqr: unsupported version")
	// ErrStateDecode indicates persisted SPQR state could not be decoded.
	ErrStateDecode = errors.New("spqr: state decode failed")
	// ErrEpochOutOfRange indicates the message epoch is out of range.
	ErrEpochOutOfRange = errors.New("spqr: epoch out of range")
	// ErrSendKeyEpochDecreased indicates send epoch went backwards.
	ErrSendKeyEpochDecreased = errors.New("spqr: send epoch decreased")
	// ErrKeyJump indicates the requested key jumps too far ahead.
	ErrKeyJump = errors.New("spqr: key jump too far")
	// ErrKeyTrimmed indicates the requested key was trimmed.
	ErrKeyTrimmed = errors.New("spqr: key trimmed")
	// ErrKeyAlreadyRequested indicates the key was already requested.
	ErrKeyAlreadyRequested = errors.New("spqr: key already requested")
	// ErrChainNotAvailable indicates chain state is missing.
	ErrChainNotAvailable = errors.New("spqr: chain not available")
	// ErrInvalidMAC indicates MAC verification failed.
	ErrInvalidMAC = errors.New("spqr: invalid mac")
	// ErrVersionMismatch indicates a negotiated version mismatch.
	ErrVersionMismatch = errors.New("spqr: version mismatch")
	// ErrMinimumVersion indicates the message version is below the minimum.
	ErrMinimumVersion = errors.New("spqr: minimum version")
	// ErrErroneousData indicates invalid data received.
	ErrErroneousData = errors.New("spqr: erroneous data")
)
