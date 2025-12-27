// Package signal provides a Go implementation of the Signal protocol building blocks.
//
// Most applications should start with Cipher. Ciphertext outputs are opaque []byte
// and session state is persisted via a store.ProtocolStore implementation.
//
// Note: Wire compatibility is in progress. Cipher uses wire-compatible formats by default,
// while EnvelopeCipher (and session.Cipher) preserve the legacy internal envelope format.
// Use DetectCiphertextFormat to route mixed ciphertexts during migration.
package signal
