// Package signal provides a Go implementation of the Signal protocol building blocks.
//
// Most applications should start with Cipher. Ciphertext outputs are opaque []byte
// and session state is persisted via a store.ProtocolStore implementation.
//
// Note: Wire compatibility is in progress. EnvelopeCipher preserves the legacy internal
// ciphertext envelope format.
package signal
