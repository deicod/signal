package signal

import signalerrors "github.com/deicod/signal/errors"

var (
	// ErrInvalidKey indicates malformed or unsupported key material.
	ErrInvalidKey = signalerrors.ErrInvalidKey
	// ErrInvalidSignature indicates a signature failed verification.
	ErrInvalidSignature = signalerrors.ErrInvalidSignature
	// ErrUntrustedIdentity indicates the remote identity key is not trusted for the given address.
	ErrUntrustedIdentity = signalerrors.ErrUntrustedIdentity

	// ErrInvalidMessage indicates a ciphertext or serialized payload is malformed or unsupported.
	ErrInvalidMessage = signalerrors.ErrInvalidMessage
	// ErrDuplicateMessage indicates the message was already processed (replay/duplicate).
	ErrDuplicateMessage = signalerrors.ErrDuplicateMessage
	// ErrInvalidMAC indicates message authentication failed (integrity/auth failure).
	ErrInvalidMAC = signalerrors.ErrInvalidMAC

	// ErrNoSession indicates no session exists for the requested peer.
	ErrNoSession = signalerrors.ErrNoSession
	// ErrNoSenderKey indicates no sender key state exists for the requested group/sender tuple.
	ErrNoSenderKey = signalerrors.ErrNoSenderKey
	// ErrSessionNotFound indicates a specific session record could not be found.
	ErrSessionNotFound = signalerrors.ErrSessionNotFound

	// ErrPreKeyNotFound indicates a required pre-key (or signed pre-key) was not available.
	ErrPreKeyNotFound = signalerrors.ErrPreKeyNotFound
	// ErrMaxSkipExceeded indicates the skipped-message-key limit was exceeded.
	ErrMaxSkipExceeded = signalerrors.ErrMaxSkipExceeded
	// ErrStaleKeyExchange indicates an unexpected pre-key bootstrap for an existing session.
	ErrStaleKeyExchange = signalerrors.ErrStaleKeyExchange

	// ErrCounterOverflow indicates a message counter overflow (send/receive).
	ErrCounterOverflow = signalerrors.ErrCounterOverflow
)
