// Package signal provides a Go implementation of the Signal protocol building blocks.
//
// Most applications should start with Cipher. Ciphertext outputs are opaque []byte
// and session state is persisted via a store.ProtocolStore implementation.
//
// Wire compatibility targets Signal's libsignal (Rust) at commit
// cfaf27f3a2d743e776ef553a770295d7e751277d. Cipher uses wire-compatible formats by
// default, while EnvelopeCipher (and session.Cipher) preserve the legacy internal
// envelope format. Use DetectCiphertextFormat to route mixed ciphertexts during migration.
//
// Supported surfaces include SignalMessage/PreKeySignalMessage wire formats,
// SenderKey group messages, sealed sender ReceivedMessage v1/v2, and SPQR v1
// for PQXDH sessions (pq_ratchet field on wire messages).
package signal
