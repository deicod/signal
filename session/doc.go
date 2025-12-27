// Package session coordinates 1:1 session state by combining X3DH bootstrap with
// Double Ratchet message state management.
//
// High-level usage is via WireCipher, which exposes byte-oriented Encrypt/Decrypt
// methods for an address in a ProtocolStore targeting libsignal wire formats.
// Cipher remains the legacy internal envelope API.
//
//	c := session.NewWireCipher(store, addr)
//	first, err := c.EncryptWithPreKeyBundle(bundle, plaintext) // bootstrap
//	plaintext, err := c.Decrypt(first)                         // receiver
//	next, err := c.Encrypt(plaintext)                          // subsequent
//	plaintext, err := c.Decrypt(next)
package session
