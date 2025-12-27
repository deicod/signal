package errors

import "errors"

var (
	// ErrInvalidKey indicates malformed or unsupported key material.
	ErrInvalidKey = errors.New("signal: invalid key")
	// ErrInvalidSignature indicates a signature failed verification.
	ErrInvalidSignature = errors.New("signal: invalid signature")
	// ErrUntrustedIdentity indicates the remote identity key is not trusted for the given address.
	ErrUntrustedIdentity = errors.New("signal: untrusted identity")

	// ErrInvalidMessage indicates a ciphertext or serialized payload is malformed or unsupported.
	ErrInvalidMessage = errors.New("signal: invalid message")
	// ErrDuplicateMessage indicates the message was already processed (replay/duplicate).
	ErrDuplicateMessage = errors.New("signal: duplicate message")
	// ErrInvalidMAC indicates message authentication failed (integrity/auth failure).
	ErrInvalidMAC = errors.New("signal: invalid mac")

	// ErrNoSession indicates no session exists for the requested peer.
	ErrNoSession = errors.New("signal: no session")
	// ErrNoSenderKey indicates no sender key state exists for the requested group/sender tuple.
	ErrNoSenderKey = errors.New("signal: no sender key")
	// ErrSessionNotFound indicates a specific session record could not be found.
	ErrSessionNotFound = errors.New("signal: session not found")

	// ErrPreKeyNotFound indicates a required pre-key (or signed pre-key) was not available.
	ErrPreKeyNotFound = errors.New("signal: pre-key not found")
	// ErrPreKeyExpired indicates a pre-key or signed pre-key is expired.
	ErrPreKeyExpired = errors.New("signal: pre-key expired")
	// ErrMaxSkipExceeded indicates the skipped-message-key limit was exceeded.
	ErrMaxSkipExceeded = errors.New("signal: max skip exceeded")
	// ErrStaleKeyExchange indicates an unexpected pre-key bootstrap for an existing session.
	ErrStaleKeyExchange = errors.New("signal: stale key exchange")

	// ErrCounterOverflow indicates a message counter overflow (send/receive).
	ErrCounterOverflow = errors.New("signal: counter overflow")
)
