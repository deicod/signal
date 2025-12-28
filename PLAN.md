# Wire-Compatible Signal Protocol Plan

This plan focuses on making the library wire-compatible with Signal/libsignal clients while
preserving existing internal APIs where feasible. All tasks below are completed and kept
checked for historical tracking.

Reference target (to lock): https://github.com/signalapp/libsignal commit `cfaf27f3a2d743e776ef553a770295d7e751277d`.

## 0. Compatibility Targets and Scope
- [x] Lock the target libsignal (Rust) version/commit and record it in docs for traceability.
- [x] List the required wire message types (SignalMessage, PreKeySignalMessage, SenderKeyMessage, SenderKeyDistributionMessage, etc.).
  - [x] SignalMessage (1:1 ciphertext payload)
  - [x] PreKeySignalMessage (1:1 session bootstrap)
  - [x] SenderKeyMessage (group ciphertext payload)
  - [x] SenderKeyDistributionMessage (group sender key setup)
- [x] Define how the internal envelope is kept as a legacy API (signal.EnvelopeCipher + migration notes).
- [x] Enumerate any required optional features (sealed sender, multi-device/Sesame, group messaging).
  - [x] Multi-device/Sesame (in scope; API present, see `sesame/`)
  - [x] Group messaging via Sender Keys (in scope; wire encoding pending, see Section 6)
  - [x] Sealed sender (scope decision pending; see Section 7)

## 1. Wire Message Formats and Serialization
- [x] Add protobuf schemas for Signal message types (1:1 and group) under `proto/`.
- [x] Generate Go protobuf code and add `google.golang.org/protobuf` to `go.mod`.
- [x] Implement message version/type encoding exactly per Signal spec (bit layout, message versioning).
- [x] Replace `protocol/*.go` custom binary serialization with protobuf-based wire encoding.
- [x] Define a stable wire codec API (e.g., `protocol/wire`) used by session and sender keys.

## 2. Identity Keys and Signatures (XEdDSA/VXEdDSA)
- [x] Implement XEdDSA/VXEdDSA signing for Curve25519 keys (per Signal spec).
- [x] Update identity signing/verification in `keys/identity.go` to use XEdDSA.
- [x] Update pre-key bundle signature creation/validation to use XEdDSA.
- [x] Add unit tests and vector tests for signature compatibility.

## 3. X3DH Alignment
- [x] Implement PQXDH (Kyber pre-key) handshake, storage hooks, and wire fields.
- [x] Verify DH ordering and inclusion rules match the spec (including optional one-time pre-key).
- [x] Align the X3DH initial message fields with the wire PreKeySignalMessage format.
- [x] Confirm HKDF info string and input concatenation match libsignal expectations.
- [x] Add X3DH interoperability vectors under `testing/vectors/`.

## 4. Double Ratchet and Message Encryption
- [x] Confirm KDF chain and message key derivation strings match libsignal.
- [x] Switch message encryption to the spec’s cipher/MAC construction (AES-CBC + HMAC or required AEAD).
- [x] Implement MAC creation/verification and any required truncation rules.
- [x] Ensure replay protection rules match spec (duplicate counters, overflow handling).
- [x] Add ratchet message vectors and integration tests for ordering/loss/duplication.
- [x] Implement SPQR (post-quantum ratchet) state and pq_ratchet key mixing for Kyber sessions.

## 5. Session and Cipher Wire Integration
- [x] Add wire message parsing/serialization alongside the existing internal envelope.
- [x] Ensure `signal.Cipher` returns/accepts wire-compatible bytes by default, with explicit legacy APIs for internal envelope usage.
- [x] Keep tests for both wire and internal envelope paths (wire interop, legacy regression).

## 5a. API Split Proposal (Wire vs Legacy)
- [x] Keep `signal.Cipher` as the wire-compatible default (Signal/libsignal format).
- [x] Add `signal.EnvelopeCipher` for the current internal envelope.
- [x] Add `session.WireCipher` to drive wire encoding explicitly.
- [x] Keep `session.Cipher` envelope helpers as `EncryptEnvelope`/`DecryptEnvelope` if a single type is preferred.
- [x] Document the migration path and how to detect/route legacy vs wire ciphertext.

### Proposed API Shapes (to implement)
- [x] `type signal.Cipher struct { inner *session.WireCipher }`
- [x] `func signal.NewCipher(store ProtocolStore, addr Address) *signal.Cipher`
- [x] `func (c *signal.Cipher) Encrypt(plaintext []byte) ([]byte, error)`
- [x] `func (c *signal.Cipher) Decrypt(ciphertext []byte) ([]byte, error)`
- [x] `func (c *signal.Cipher) EncryptWithPreKeyBundle(bundle *PreKeyBundle, plaintext []byte) ([]byte, error)`

- [x] `type signal.EnvelopeCipher struct { inner *session.Cipher }`
- [x] `func signal.NewEnvelopeCipher(store ProtocolStore, addr Address) *signal.EnvelopeCipher`
- [x] `func (c *signal.EnvelopeCipher) Encrypt(plaintext []byte) ([]byte, error)`
- [x] `func (c *signal.EnvelopeCipher) Decrypt(ciphertext []byte) ([]byte, error)`
- [x] `func (c *signal.EnvelopeCipher) EncryptWithPreKeyBundle(bundle *PreKeyBundle, plaintext []byte) ([]byte, error)`

- [x] `type session.WireCipher struct { store ProtocolStore; remoteAddress Address; builder *Builder }`
- [x] `func session.NewWireCipher(store ProtocolStore, addr Address) *session.WireCipher`
- [x] `func (c *session.WireCipher) Encrypt(plaintext []byte) ([]byte, error)`
- [x] `func (c *session.WireCipher) Decrypt(ciphertext []byte) ([]byte, error)`
- [x] `func (c *session.WireCipher) EncryptWithPreKeyBundle(bundle *keys.PreKeyBundle, plaintext []byte) ([]byte, error)`
- [x] Update tests to exercise the wire codec path for Encrypt/Decrypt.

## 6. Group Messaging (Sender Keys)
- [x] Replace `senderkeys` custom magic-byte format with protobuf wire encoding.
- [x] Verify sender key ratchet, signature scheme, and MAC rules match spec.
- [x] Add sender key distribution/message vectors and interoperability tests.

## 7. Sealed Sender (If Required)
- [x] Decide on sealed sender support and scope (certs, sender info, anonymous sender).
  - [x] Scope: v1 + v2 ReceivedMessage; no multi-recipient SentMessage builder.
- [x] Implement sealed sender envelope and certificate handling if required.
- [x] Add tests for sealed sender encoding/decoding and session interaction.

## 8. Storage and Security Hardening
- [x] Add store requirements for signed pre-key expiry and session limits.
- [x] Enforce public key validation everywhere inputs enter the protocol.
- [x] Expand key zeroization beyond X3DH (ratchet, sender keys, session teardown).
- [x] Review constant-time comparisons in all authentication paths.

## 9. Test Vectors and Interop Harness
- [x] Add official vectors for X3DH, Double Ratchet, and sender keys in `testing/vectors/`.
- [x] Add deterministic X3DH/ratchet vector files for the current implementation.
- [x] Implement a vector runner to validate serialization and cryptographic outputs.
- [x] Add cross-implementation fixtures (generated from libsignal) where possible.
- [x] Validate libsignal session fixture decryption once SPQR support is in place.
- [x] Add fuzzing for wire deserialization and message processing.

## 10. Docs and Migration
- [x] Update README and GoDoc to state wire compatibility and supported versions.
- [x] Document any breaking API changes and migration guidance from the internal envelope.
- [x] Add protocol compatibility notes and security considerations.
