# Signal Protocol Implementation Specification for Go

## Project Overview

**Goal**: Implement the Signal Protocol as a reusable, well-tested Go package for end-to-end encrypted messaging.

**Target**: Production-ready library suitable for integration into messaging applications.

**References**:
- [X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/)
- [Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)
- [Sesame Algorithm](https://signal.org/docs/specifications/sesame/) (multi-device)
- [XEdDSA and VXEdDSA](https://signal.org/docs/specifications/xeddsa/)

---

## Package Structure

```
signal/
├── go.mod
├── go.sum
├── README.md
├── doc.go                    # Package-level documentation
│
├── crypto/                   # Low-level cryptographic primitives
│   ├── curve25519.go         # Curve25519 operations
│   ├── aead.go               # AEAD encryption (AES-GCM / ChaCha20-Poly1305)
│   ├── hkdf.go               # HKDF key derivation
│   ├── hmac.go               # HMAC operations
│   └── random.go             # Secure random generation
│
├── keys/                     # Key types and management
│   ├── identity.go           # Identity key pair
│   ├── prekey.go             # Pre-key and signed pre-key
│   ├── ephemeral.go          # Ephemeral keys
│   ├── bundle.go             # Pre-key bundles
│   └── serialize.go          # Key serialization/deserialization
│
├── x3dh/                     # X3DH key agreement
│   ├── x3dh.go               # Core X3DH implementation
│   ├── initiator.go          # Alice's side of handshake
│   ├── responder.go          # Bob's side of handshake
│   └── shared_secret.go      # Shared secret derivation
│
├── ratchet/                  # Double Ratchet algorithm
│   ├── state.go              # Ratchet state structure
│   ├── chain.go              # Symmetric key ratchet (KDF chain)
│   ├── dh_ratchet.go         # DH ratchet operations
│   ├── encrypt.go            # Message encryption
│   ├── decrypt.go            # Message decryption
│   ├── header.go             # Message header structure
│   └── skipped.go            # Skipped message keys handling
│
├── session/                  # Session management
│   ├── session.go            # Session state
│   ├── builder.go            # Session initialization
│   ├── cipher.go             # High-level encrypt/decrypt
│   └── record.go             # Session record (multiple sessions per recipient)
│
├── protocol/                 # Wire protocol
│   ├── message.go            # Message structures
│   ├── prekey_message.go     # Pre-key message (initial message)
│   ├── signal_message.go     # Standard Signal message
│   └── serialize.go          # Protocol buffer / serialization
│
├── store/                    # Storage interfaces
│   ├── identity_store.go     # Identity key storage interface
│   ├── prekey_store.go       # Pre-key storage interface
│   ├── session_store.go      # Session storage interface
│   ├── signed_prekey_store.go
│   └── memory/               # In-memory implementation (for testing)
│       └── memory_store.go
│
├── errors/                   # Custom error types
│   └── errors.go
│
└── testing/                  # Test utilities
    ├── vectors/              # Test vectors from Signal specs
    └── helpers.go
```

---

## Milestones

### Milestone 1: Cryptographic Foundation
**Duration**: 1-2 weeks  
**Goal**: Implement and test all low-level cryptographic primitives.

---

#### Task 1.1: Project Setup
**Priority**: Critical  
**Estimated Time**: 2-4 hours

- [x] Initialize Go module (`go mod init github.com/<user>/signal`)
- [x] Set up directory structure as outlined above
- [x] Configure CI/CD pipeline (GitHub Actions)
- [x] Set up linting (golangci-lint) and formatting
- [x] Create initial README with project goals
- [x] Add LICENSE file (recommend Apache 2.0 or MIT)
- [x] Create `.gitignore`

**Acceptance Criteria**:
- `go build ./...` succeeds
- CI pipeline runs on push
- Linting passes with zero warnings

---

#### Task 1.2: Curve25519 Operations
**Priority**: Critical  
**Estimated Time**: 4-6 hours

**File**: `crypto/curve25519.go`

- [x] Implement key pair generation
  ```go
  type KeyPair struct {
      PublicKey  [32]byte
      PrivateKey [32]byte
  }
  
  func GenerateKeyPair() (*KeyPair, error)
  ```
- [x] Implement Diffie-Hellman shared secret calculation
  ```go
  func DH(privateKey, publicKey [32]byte) ([32]byte, error)
  ```
- [x] Use `golang.org/x/crypto/curve25519` as underlying implementation
- [x] Add input validation (check for low-order points)
- [x] Write comprehensive unit tests
- [x] Benchmark performance

**Acceptance Criteria**:
- All test vectors from Signal spec pass
- DH operation completes in < 1ms on modern hardware
- Handles edge cases (zero keys, invalid inputs)

---

#### Task 1.3: HKDF Implementation
**Priority**: Critical  
**Estimated Time**: 3-4 hours

**File**: `crypto/hkdf.go`

- [x] Implement HKDF-SHA256 extract
  ```go
  func HKDFExtract(salt, inputKeyMaterial []byte) []byte
  ```
- [x] Implement HKDF-SHA256 expand
  ```go
  func HKDFExpand(prk []byte, info []byte, length int) []byte
  ```
- [x] Implement combined HKDF
  ```go
  func HKDF(inputKeyMaterial, salt, info []byte, length int) ([]byte, error)
  ```
- [x] Use `golang.org/x/crypto/hkdf`
- [x] Validate against RFC 5869 test vectors
- [x] Write unit tests

**Acceptance Criteria**:
- RFC 5869 test vectors pass
- Signal-specific KDF derivations work correctly

---

#### Task 1.4: AEAD Encryption
**Priority**: Critical  
**Estimated Time**: 4-5 hours

**File**: `crypto/aead.go`

- [x] Implement AES-256-GCM encryption/decryption
  ```go
  func AESGCMEncrypt(key, plaintext, associatedData []byte) (ciphertext, nonce []byte, err error)
  func AESGCMDecrypt(key, ciphertext, nonce, associatedData []byte) ([]byte, error)
  ```
- [x] Implement ChaCha20-Poly1305 as alternative
  ```go
  func ChaChaEncrypt(key, plaintext, associatedData []byte) (ciphertext, nonce []byte, err error)
  func ChaChaDecrypt(key, ciphertext, nonce, associatedData []byte) ([]byte, error)
  ```
- [x] Create unified AEAD interface
  ```go
  type AEAD interface {
      Encrypt(key, plaintext, ad []byte) ([]byte, error)
      Decrypt(key, ciphertext, ad []byte) ([]byte, error)
      KeySize() int
      NonceSize() int
  }
  ```
- [x] Secure nonce generation (random or counter-based)
- [x] Write unit tests with known test vectors

**Acceptance Criteria**:
- Both AES-GCM and ChaCha20-Poly1305 implementations pass standard test vectors
- Interface allows easy swapping of algorithms
- Nonces are never reused

---

#### Task 1.5: HMAC Operations
**Priority**: High  
**Estimated Time**: 2-3 hours

**File**: `crypto/hmac.go`

- [x] Implement HMAC-SHA256
  ```go
  func HMAC256(key, data []byte) []byte
  ```
- [x] Implement HMAC-SHA512
  ```go
  func HMAC512(key, data []byte) []byte
  ```
- [x] Implement constant-time comparison
  ```go
  func HMACVerify(key, data, expectedMAC []byte) bool
  ```
- [x] Write unit tests

**Acceptance Criteria**:
- Constant-time comparison prevents timing attacks
- Standard HMAC test vectors pass

---

#### Task 1.6: Secure Random Generation
**Priority**: Critical  
**Estimated Time**: 1-2 hours

**File**: `crypto/random.go`

- [x] Implement secure random byte generation
  ```go
  func RandomBytes(length int) ([]byte, error)
  ```
- [x] Implement random scalar generation for Curve25519
- [x] Use `crypto/rand` from standard library
- [x] Add fallback handling for entropy exhaustion

**Acceptance Criteria**:
- Uses OS-provided CSPRNG
- Fails safely if entropy unavailable

---

### Milestone 2: Key Management
**Duration**: 1-2 weeks  
**Goal**: Implement all key types, serialization, and storage interfaces.

---

#### Task 2.1: Identity Keys
**Priority**: Critical  
**Estimated Time**: 4-5 hours

**File**: `keys/identity.go`

- [ ] Define identity key pair structure
  ```go
  type IdentityKeyPair struct {
      PublicKey  IdentityKey
      PrivateKey [32]byte
  }
  
  type IdentityKey struct {
      PublicKey [32]byte
  }
  ```
- [ ] Implement generation
  ```go
  func GenerateIdentityKeyPair() (*IdentityKeyPair, error)
  ```
- [ ] Implement signing using XEdDSA (Curve25519 -> Ed25519 conversion)
  ```go
  func (k *IdentityKeyPair) Sign(message []byte) ([]byte, error)
  func (k *IdentityKey) Verify(message, signature []byte) bool
  ```
- [ ] Implement fingerprint generation
  ```go
  func (k *IdentityKey) Fingerprint() string
  ```
- [ ] Write unit tests

**Notes**: XEdDSA allows using Curve25519 keys for both DH and signing. See Signal's XEdDSA spec.

**Acceptance Criteria**:
- Keys can be used for both DH and signing
- Fingerprints match Signal's format
- Signatures verify correctly

---

#### Task 2.2: Pre-Keys
**Priority**: Critical  
**Estimated Time**: 4-5 hours

**File**: `keys/prekey.go`

- [ ] Define pre-key structure
  ```go
  type PreKey struct {
      ID        uint32
      KeyPair   *crypto.KeyPair
      Timestamp time.Time
  }
  ```
- [ ] Define signed pre-key structure
  ```go
  type SignedPreKey struct {
      ID        uint32
      KeyPair   *crypto.KeyPair
      Signature []byte
      Timestamp time.Time
  }
  ```
- [ ] Implement pre-key generation
  ```go
  func GeneratePreKey(id uint32) (*PreKey, error)
  func GeneratePreKeys(startID uint32, count int) ([]*PreKey, error)
  ```
- [ ] Implement signed pre-key generation
  ```go
  func GenerateSignedPreKey(identityKey *IdentityKeyPair, id uint32) (*SignedPreKey, error)
  ```
- [ ] Implement signature verification
- [ ] Write unit tests

**Acceptance Criteria**:
- Signed pre-key signatures verify against identity key
- Batch generation works correctly
- IDs are unique and sequential

---

#### Task 2.3: Pre-Key Bundles
**Priority**: Critical  
**Estimated Time**: 3-4 hours

**File**: `keys/bundle.go`

- [ ] Define pre-key bundle structure (published to server)
  ```go
  type PreKeyBundle struct {
      RegistrationID       uint32
      DeviceID             uint32
      PreKeyID             *uint32      // Optional
      PreKeyPublic         *[32]byte    // Optional
      SignedPreKeyID       uint32
      SignedPreKeyPublic   [32]byte
      SignedPreKeySignature []byte
      IdentityKey          IdentityKey
  }
  ```
- [ ] Implement bundle creation
- [ ] Implement bundle validation
  ```go
  func (b *PreKeyBundle) Validate() error
  ```
- [ ] Write unit tests

**Acceptance Criteria**:
- Bundle validation catches invalid signatures
- Optional one-time pre-key handled correctly

---

#### Task 2.4: Key Serialization
**Priority**: High  
**Estimated Time**: 4-6 hours

**File**: `keys/serialize.go`

- [ ] Choose serialization format (Protocol Buffers recommended)
- [ ] Define `.proto` files for all key types
- [ ] Implement serialization for all key types
  ```go
  func (k *IdentityKey) Serialize() ([]byte, error)
  func DeserializeIdentityKey(data []byte) (*IdentityKey, error)
  ```
- [ ] Implement for PreKey, SignedPreKey, PreKeyBundle
- [ ] Add versioning to serialization format
- [ ] Write unit tests (round-trip tests)

**Acceptance Criteria**:
- All key types serialize/deserialize correctly
- Versioning allows future format changes
- Invalid data returns clear errors

---

#### Task 2.5: Storage Interfaces
**Priority**: High  
**Estimated Time**: 5-6 hours

**Files**: `store/*.go`

- [ ] Define identity key store interface
  ```go
  type IdentityKeyStore interface {
      GetIdentityKeyPair() (*IdentityKeyPair, error)
      GetLocalRegistrationID() (uint32, error)
      SaveIdentity(address Address, identityKey *IdentityKey) error
      IsTrustedIdentity(address Address, identityKey *IdentityKey, direction Direction) bool
      GetIdentity(address Address) (*IdentityKey, error)
  }
  ```
- [ ] Define pre-key store interface
  ```go
  type PreKeyStore interface {
      LoadPreKey(id uint32) (*PreKey, error)
      StorePreKey(id uint32, preKey *PreKey) error
      ContainsPreKey(id uint32) bool
      RemovePreKey(id uint32) error
  }
  ```
- [ ] Define signed pre-key store interface
  ```go
  type SignedPreKeyStore interface {
      LoadSignedPreKey(id uint32) (*SignedPreKey, error)
      StoreSignedPreKey(id uint32, signedPreKey *SignedPreKey) error
      ContainsSignedPreKey(id uint32) bool
      RemoveSignedPreKey(id uint32) error
  }
  ```
- [ ] Define session store interface
  ```go
  type SessionStore interface {
      LoadSession(address Address) (*SessionRecord, error)
      StoreSession(address Address, record *SessionRecord) error
      ContainsSession(address Address) bool
      DeleteSession(address Address) error
      DeleteAllSessions(name string) error
  }
  ```
- [ ] Define combined protocol store interface
  ```go
  type ProtocolStore interface {
      IdentityKeyStore
      PreKeyStore
      SignedPreKeyStore
      SessionStore
  }
  ```
- [ ] Implement in-memory store for testing
- [ ] Write unit tests for in-memory implementation

**Acceptance Criteria**:
- Interfaces are complete and allow any backend
- In-memory implementation passes all tests
- Thread-safe considerations documented

---

### Milestone 3: X3DH Key Agreement
**Duration**: 1-2 weeks  
**Goal**: Implement the complete X3DH handshake protocol.

---

#### Task 3.1: X3DH Initiator (Alice)
**Priority**: Critical  
**Estimated Time**: 6-8 hours

**File**: `x3dh/initiator.go`

- [ ] Implement initial message creation
  ```go
  type X3DHInitiator struct {
      identityKey *IdentityKeyPair
      ephemeralKey *crypto.KeyPair
  }
  
  func NewX3DHInitiator(identityKey *IdentityKeyPair) *X3DHInitiator
  
  func (x *X3DHInitiator) ProcessPreKeyBundle(bundle *PreKeyBundle) (*X3DHResult, error)
  ```
- [ ] Implement DH calculations per spec:
  - DH1 = DH(IKa, SPKb)
  - DH2 = DH(EKa, IKb)
  - DH3 = DH(EKa, SPKb)
  - DH4 = DH(EKa, OPKb) [if one-time pre-key present]
- [ ] Implement shared secret derivation
  ```go
  SK = HKDF(DH1 || DH2 || DH3 || DH4, salt=0, info="X3DH")
  ```
- [ ] Create initial message structure
  ```go
  type X3DHMessage struct {
      IdentityKey    IdentityKey
      EphemeralKey   [32]byte
      PreKeyID       *uint32
      SignedPreKeyID uint32
      Ciphertext     []byte  // First Double Ratchet message
  }
  ```
- [ ] Handle case without one-time pre-key
- [ ] Write unit tests

**Acceptance Criteria**:
- Produces correct shared secret per X3DH spec
- Works with and without one-time pre-key
- Initial message contains all required fields

---

#### Task 3.2: X3DH Responder (Bob)
**Priority**: Critical  
**Estimated Time**: 6-8 hours

**File**: `x3dh/responder.go`

- [ ] Implement message processing
  ```go
  type X3DHResponder struct {
      identityKey    *IdentityKeyPair
      signedPreKey   *SignedPreKey
      preKeyStore    PreKeyStore
  }
  
  func NewX3DHResponder(identityKey *IdentityKeyPair, signedPreKey *SignedPreKey, store PreKeyStore) *X3DHResponder
  
  func (x *X3DHResponder) ProcessInitialMessage(msg *X3DHMessage) (*X3DHResult, error)
  ```
- [ ] Implement DH calculations (Bob's side):
  - DH1 = DH(SPKb, IKa)
  - DH2 = DH(IKb, EKa)
  - DH3 = DH(SPKb, EKa)
  - DH4 = DH(OPKb, EKa) [if one-time pre-key was used]
- [ ] Delete one-time pre-key after use
- [ ] Derive same shared secret as initiator
- [ ] Write unit tests

**Acceptance Criteria**:
- Derives identical shared secret as initiator
- One-time pre-key deleted after use
- Validates identity key trust

---

#### Task 3.3: X3DH Result and Associated Data
**Priority**: High  
**Estimated Time**: 3-4 hours

**File**: `x3dh/shared_secret.go`

- [ ] Define X3DH result structure
  ```go
  type X3DHResult struct {
      SharedSecret   [32]byte
      AssociatedData []byte
      RemoteIdentity IdentityKey
  }
  ```
- [ ] Implement associated data calculation
  ```go
  AD = Encode(IKa) || Encode(IKb)
  ```
- [ ] Clear sensitive data after use
- [ ] Write unit tests

**Acceptance Criteria**:
- Associated data matches spec
- Shared secret securely wiped when no longer needed

---

#### Task 3.4: X3DH Integration Tests
**Priority**: High  
**Estimated Time**: 4-5 hours

**File**: `x3dh/x3dh_test.go`

- [ ] Test complete handshake (Alice → Bob)
- [ ] Test handshake without one-time pre-key
- [ ] Test with invalid/expired signed pre-key
- [ ] Test with wrong identity key
- [ ] Test replay attack prevention
- [ ] Add fuzzing tests
- [ ] Benchmark performance

**Acceptance Criteria**:
- Full handshake completes successfully
- Error cases handled gracefully
- No panics under fuzzing

---

### Milestone 4: Double Ratchet Algorithm
**Duration**: 2-3 weeks  
**Goal**: Implement the complete Double Ratchet for message encryption.

---

#### Task 4.1: Ratchet State Structure
**Priority**: Critical  
**Estimated Time**: 4-5 hours

**File**: `ratchet/state.go`

- [ ] Define ratchet state structure
  ```go
  type State struct {
      // DH Ratchet
      DHs       *crypto.KeyPair  // Our current DH key pair
      DHr       *[32]byte        // Their current DH public key
      
      // Root key
      RK        [32]byte
      
      // Chain keys
      CKs       [32]byte         // Sending chain key
      CKr       [32]byte         // Receiving chain key
      
      // Message numbers
      Ns        uint32           // Send message number
      Nr        uint32           // Receive message number
      PN        uint32           // Previous chain length
      
      // Skipped message keys
      MKSkipped map[SkippedKey][32]byte
  }
  
  type SkippedKey struct {
      PublicKey [32]byte
      N         uint32
  }
  ```
- [ ] Implement state initialization from X3DH result
  ```go
  func InitializeState(x3dhResult *X3DHResult, isInitiator bool) (*State, error)
  ```
- [ ] Implement state cloning (for atomic operations)
- [ ] Write unit tests

**Acceptance Criteria**:
- State properly initialized from X3DH
- All fields correctly set based on role (initiator vs responder)

---

#### Task 4.2: KDF Chain (Symmetric Ratchet)
**Priority**: Critical  
**Estimated Time**: 4-5 hours

**File**: `ratchet/chain.go`

- [ ] Implement chain key derivation
  ```go
  func KDFChain(chainKey [32]byte) (newChainKey, messageKey [32]byte)
  ```
- [ ] Use HMAC-SHA256 with different constants:
  - Chain key: HMAC(CK, 0x02)
  - Message key: HMAC(CK, 0x01)
- [ ] Implement message key derivation for encryption
  ```go
  func DeriveMessageKeys(messageKey [32]byte) (encKey, authKey, iv []byte)
  ```
- [ ] Write unit tests with test vectors

**Acceptance Criteria**:
- Chain advances correctly
- Message keys are unique per message
- Matches Signal spec test vectors

---

#### Task 4.3: DH Ratchet
**Priority**: Critical  
**Estimated Time**: 5-6 hours

**File**: `ratchet/dh_ratchet.go`

- [ ] Implement root key KDF
  ```go
  func KDFRoot(rootKey [32]byte, dhOutput [32]byte) (newRootKey, chainKey [32]byte)
  ```
- [ ] Implement DH ratchet step
  ```go
  func (s *State) DHRatchet(theirPublicKey [32]byte) error
  ```
- [ ] Handle ratchet on receiving new DH key
- [ ] Handle ratchet before sending
- [ ] Write unit tests

**Acceptance Criteria**:
- Root key updates correctly
- New chain keys derived properly
- Forward secrecy maintained

---

#### Task 4.4: Message Header
**Priority**: High  
**Estimated Time**: 3-4 hours

**File**: `ratchet/header.go`

- [ ] Define header structure
  ```go
  type Header struct {
      DH [32]byte  // Sender's current DH public key
      PN uint32    // Previous chain message count
      N  uint32    // Message number in current chain
  }
  ```
- [ ] Implement header serialization
  ```go
  func (h *Header) Serialize() []byte
  func DeserializeHeader(data []byte) (*Header, error)
  ```
- [ ] Implement header encryption (optional, for metadata protection)
- [ ] Write unit tests

**Acceptance Criteria**:
- Header correctly serialized/deserialized
- Size is minimal

---

#### Task 4.5: Message Encryption
**Priority**: Critical  
**Estimated Time**: 5-6 hours

**File**: `ratchet/encrypt.go`

- [ ] Implement encryption function
  ```go
  func (s *State) Encrypt(plaintext, associatedData []byte) (*Message, error)
  ```
- [ ] Steps:
  1. If first message or DHr changed, perform DH ratchet
  2. Derive message key from sending chain
  3. Advance sending chain
  4. Encrypt plaintext with message key
  5. Create and return message with header
- [ ] Handle associated data properly
- [ ] Write unit tests

**Acceptance Criteria**:
- Messages encrypt correctly
- Chain advances after each encryption
- Associated data authenticated

---

#### Task 4.6: Message Decryption
**Priority**: Critical  
**Estimated Time**: 6-8 hours

**File**: `ratchet/decrypt.go`

- [ ] Implement decryption function
  ```go
  func (s *State) Decrypt(message *Message, associatedData []byte) ([]byte, error)
  ```
- [ ] Steps:
  1. Check if message key is in skipped keys
  2. If new DH key, perform DH ratchet(s)
  3. Skip any missed messages, storing their keys
  4. Derive message key
  5. Decrypt and return plaintext
- [ ] Handle out-of-order messages
- [ ] Handle duplicate messages
- [ ] Write unit tests

**Acceptance Criteria**:
- Decrypts in-order messages correctly
- Handles out-of-order messages
- Properly stores skipped keys

---

#### Task 4.7: Skipped Message Keys
**Priority**: High  
**Estimated Time**: 4-5 hours

**File**: `ratchet/skipped.go`

- [ ] Implement skipped key storage
  ```go
  func (s *State) skipMessageKeys(until uint32) error
  ```
- [ ] Implement skipped key lookup
  ```go
  func (s *State) trySkippedMessageKey(header *Header) (*[32]byte, error)
  ```
- [ ] Implement max skip limit (prevent DoS)
  ```go
  const MaxSkip = 1000
  ```
- [ ] Implement skipped key cleanup (age-based)
- [ ] Write unit tests

**Acceptance Criteria**:
- Out-of-order messages within limit work
- DoS protection via max skip
- Old skipped keys cleaned up

---

#### Task 4.8: Double Ratchet Integration Tests
**Priority**: Critical  
**Estimated Time**: 6-8 hours

**File**: `ratchet/ratchet_test.go`

- [ ] Test simple back-and-forth conversation
- [ ] Test one-sided conversation (many messages, no response)
- [ ] Test out-of-order message delivery
- [ ] Test message loss and recovery
- [ ] Test max skip limit
- [ ] Test with actual X3DH initialization
- [ ] Add fuzzing tests
- [ ] Benchmark performance

**Acceptance Criteria**:
- All conversation patterns work correctly
- No state corruption under any sequence
- Performance acceptable (< 1ms per message)

---

### Milestone 5: Session Management
**Duration**: 1-2 weeks  
**Goal**: Implement high-level session management and message protocol.

---

#### Task 5.1: Session State
**Priority**: Critical  
**Estimated Time**: 4-5 hours

**File**: `session/session.go`

- [ ] Define session state structure
  ```go
  type Session struct {
      ratchetState    *ratchet.State
      localIdentity   *IdentityKey
      remoteIdentity  *IdentityKey
      associatedData  []byte
      previousStates  []*ratchet.State  // For handling delayed messages
  }
  ```
- [ ] Implement session version tracking
- [ ] Implement session archiving (for key rotation)
- [ ] Write unit tests

**Acceptance Criteria**:
- Session properly encapsulates ratchet state
- Version tracked for protocol upgrades

---

#### Task 5.2: Session Builder
**Priority**: Critical  
**Estimated Time**: 5-6 hours

**File**: `session/builder.go`

- [ ] Implement session builder
  ```go
  type SessionBuilder struct {
      store         ProtocolStore
      remoteAddress Address
  }
  
  func NewSessionBuilder(store ProtocolStore, address Address) *SessionBuilder
  ```
- [ ] Implement outgoing session creation
  ```go
  func (b *SessionBuilder) ProcessPreKeyBundle(bundle *PreKeyBundle) error
  ```
- [ ] Implement incoming session creation
  ```go
  func (b *SessionBuilder) ProcessPreKeyMessage(message *PreKeyMessage) (*Session, []byte, error)
  ```
- [ ] Handle identity key trust decisions
- [ ] Write unit tests

**Acceptance Criteria**:
- Sessions created correctly from bundles
- Pre-key messages processed correctly
- Identity trust checks enforced

---

#### Task 5.3: Session Cipher
**Priority**: Critical  
**Estimated Time**: 4-5 hours

**File**: `session/cipher.go`

- [ ] Implement high-level cipher
  ```go
  type SessionCipher struct {
      store         ProtocolStore
      remoteAddress Address
  }
  
  func NewSessionCipher(store ProtocolStore, address Address) *SessionCipher
  ```
- [ ] Implement encryption
  ```go
  func (c *SessionCipher) Encrypt(plaintext []byte) (*CiphertextMessage, error)
  ```
- [ ] Implement decryption
  ```go
  func (c *SessionCipher) Decrypt(message *CiphertextMessage) ([]byte, error)
  ```
- [ ] Auto-detect message type (pre-key vs regular)
- [ ] Write unit tests

**Acceptance Criteria**:
- High-level API is simple to use
- Correct message type used automatically
- Sessions persisted after operations

---

#### Task 5.4: Session Record
**Priority**: High  
**Estimated Time**: 4-5 hours

**File**: `session/record.go`

- [ ] Define session record (handles multiple sessions)
  ```go
  type SessionRecord struct {
      currentSession  *Session
      previousSessions []*Session
  }
  ```
- [ ] Implement session promotion
- [ ] Implement session archival
- [ ] Implement serialization
- [ ] Handle max archived sessions
- [ ] Write unit tests

**Acceptance Criteria**:
- Multiple sessions per recipient handled
- Old sessions archived correctly
- Serialization round-trips correctly

---

#### Task 5.5: Protocol Messages
**Priority**: High  
**Estimated Time**: 5-6 hours

**Files**: `protocol/*.go`

- [ ] Define base message interface
  ```go
  type CiphertextMessage interface {
      Type() CiphertextType
      Serialize() []byte
  }
  
  type CiphertextType int
  const (
      PreKeyType CiphertextType = iota
      SignalType
  )
  ```
- [ ] Implement Signal message (regular message)
  ```go
  type SignalMessage struct {
      Version          uint8
      RatchetKey       [32]byte
      Counter          uint32
      PreviousCounter  uint32
      Ciphertext       []byte
      MAC              []byte
  }
  ```
- [ ] Implement Pre-key message (initial message)
  ```go
  type PreKeyMessage struct {
      Version           uint8
      RegistrationID    uint32
      PreKeyID          *uint32
      SignedPreKeyID    uint32
      BaseKey           [32]byte
      IdentityKey       IdentityKey
      SignalMessage     *SignalMessage
  }
  ```
- [ ] Implement serialization (Protocol Buffers)
- [ ] Implement MAC calculation and verification
- [ ] Write unit tests

**Acceptance Criteria**:
- Message formats match Signal spec
- MAC verification prevents tampering
- Versioning allows future upgrades

---

### Milestone 6: Error Handling and Security
**Duration**: 1 week  
**Goal**: Implement comprehensive error handling and security hardening.

---

#### Task 6.1: Custom Error Types
**Priority**: High  
**Estimated Time**: 3-4 hours

**File**: `errors/errors.go`

- [ ] Define error types
  ```go
  var (
      ErrInvalidKey           = errors.New("invalid key")
      ErrInvalidSignature     = errors.New("invalid signature")
      ErrUntrustedIdentity    = errors.New("untrusted identity")
      ErrInvalidMessage       = errors.New("invalid message")
      ErrDuplicateMessage     = errors.New("duplicate message")
      ErrInvalidMAC           = errors.New("invalid MAC")
      ErrNoSession            = errors.New("no session")
      ErrSessionNotFound      = errors.New("session not found")
      ErrPreKeyNotFound       = errors.New("pre-key not found")
      ErrMaxSkipExceeded      = errors.New("max skip exceeded")
      ErrStaleKeyExchange     = errors.New("stale key exchange")
  )
  ```
- [ ] Implement error wrapping with context
- [ ] Document error handling for users
- [ ] Write tests for error conditions

**Acceptance Criteria**:
- All error conditions have specific errors
- Errors can be unwrapped for type checking
- Sensitive info not leaked in errors

---

#### Task 6.2: Security Hardening
**Priority**: Critical  
**Estimated Time**: 4-6 hours

- [ ] Implement secure memory zeroing
  ```go
  func ZeroBytes(b []byte)
  func ZeroKey(k *[32]byte)
  ```
- [ ] Add `defer ZeroBytes()` after all key operations
- [ ] Validate all public key inputs
- [ ] Check for all-zero keys (small subgroup attack)
- [ ] Implement constant-time comparisons everywhere
- [ ] Review for timing side-channels
- [ ] Add security documentation

**Acceptance Criteria**:
- Keys zeroed after use
- No timing side-channels
- Input validation prevents misuse

---

#### Task 6.3: Replay Attack Prevention
**Priority**: High  
**Estimated Time**: 3-4 hours

- [ ] Track seen message counters per chain
- [ ] Reject duplicate message numbers
- [ ] Handle counter overflow
- [ ] Document replay protection mechanism
- [ ] Write tests for replay attacks

**Acceptance Criteria**:
- Duplicate messages rejected
- Counter overflow handled safely

---

### Milestone 7: Testing and Documentation
**Duration**: 1-2 weeks  
**Goal**: Comprehensive testing suite and documentation.

---

#### Task 7.1: Test Vectors
**Priority**: High  
**Estimated Time**: 4-5 hours

**Directory**: `testing/vectors/`

- [ ] Add official Signal test vectors (if available)
- [ ] Create comprehensive test vector files
- [ ] X3DH test vectors
- [ ] Double Ratchet test vectors
- [ ] AEAD test vectors
- [ ] Implement test vector runner
- [ ] Document test vector format

**Acceptance Criteria**:
- All implementations pass test vectors
- Easy to add new vectors

---

#### Task 7.2: Integration Test Suite
**Priority**: Critical  
**Estimated Time**: 6-8 hours

- [ ] Full conversation test (Alice ↔ Bob)
- [ ] Multi-party conversation simulation
- [ ] Network condition simulation:
  - Message reordering
  - Message loss
  - Message duplication
- [ ] Long conversation test (1000+ messages)
- [ ] Identity key change scenarios
- [ ] Session reset scenarios
- [ ] Write benchmarks

**Acceptance Criteria**:
- All realistic scenarios tested
- No state corruption detected
- Performance benchmarks documented

---

#### Task 7.3: Fuzzing
**Priority**: High  
**Estimated Time**: 4-5 hours

- [ ] Set up go-fuzz or native fuzzing
- [ ] Fuzz deserialization functions
- [ ] Fuzz decryption with random inputs
- [ ] Fuzz message processing
- [ ] Run extended fuzzing campaign
- [ ] Fix any issues found

**Acceptance Criteria**:
- No panics under fuzzing
- No memory safety issues
- 24+ hour fuzz run passes

---

#### Task 7.4: Documentation
**Priority**: High  
**Estimated Time**: 6-8 hours

- [ ] Write comprehensive README
  - Installation
  - Quick start
  - Examples
  - Security considerations
- [ ] Document all public APIs (GoDoc)
- [ ] Create example applications:
  - Simple CLI chat
  - Basic server integration
- [ ] Write security documentation
- [ ] Write migration guide (for future versions)
- [ ] Create architecture diagram

**Acceptance Criteria**:
- README covers all basics
- All public APIs documented
- Examples compile and run

---

### Milestone 8: Polish and Release
**Duration**: 1 week  
**Goal**: Prepare for initial release.

---

#### Task 8.1: API Review
**Priority**: High  
**Estimated Time**: 3-4 hours

- [ ] Review all public APIs for consistency
- [ ] Ensure idiomatic Go naming
- [ ] Check for unnecessary exports
- [ ] Validate error handling patterns
- [ ] Review thread-safety documentation

**Acceptance Criteria**:
- API is clean and consistent
- Only necessary symbols exported

---

#### Task 8.2: Performance Optimization
**Priority**: Medium  
**Estimated Time**: 4-5 hours

- [ ] Profile CPU usage
- [ ] Profile memory allocations
- [ ] Optimize hot paths
- [ ] Reduce allocations where possible
- [ ] Document performance characteristics

**Acceptance Criteria**:
- Key operations < 1ms
- Memory usage reasonable
- No obvious inefficiencies

---

#### Task 8.3: Release Preparation
**Priority**: High  
**Estimated Time**: 3-4 hours

- [ ] Finalize version number (v0.1.0)
- [ ] Create CHANGELOG.md
- [ ] Review and finalize LICENSE
- [ ] Create CONTRIBUTING.md
- [ ] Set up issue templates
- [ ] Create release on GitHub
- [ ] Publish documentation

**Acceptance Criteria**:
- Clean initial release
- All documentation complete
- CI/CD fully functional

---

## Optional Future Milestones

### Milestone 9: Multi-Device Support (Sesame)
- Implement Sesame algorithm for multi-device messaging
- Handle device-to-device encryption

### Milestone 10: Group Messaging
- Implement Sender Keys for efficient group messaging
- Handle group member changes

### Milestone 11: Additional Backends
- SQLite storage backend
- PostgreSQL storage backend
- Redis storage backend

---

## Dependencies

### Required Go Dependencies
```go
require (
    golang.org/x/crypto v0.x.x      // Curve25519, HKDF, ChaCha20-Poly1305
    google.golang.org/protobuf v1.x.x  // Protocol Buffers
)
```

### Development Dependencies
```go
require (
    github.com/stretchr/testify v1.x.x  // Testing assertions
)
```

---

## Security Considerations

1. **Memory Safety**: Zero sensitive data immediately after use
2. **Side Channels**: Use constant-time operations for all comparisons
3. **Random Numbers**: Only use `crypto/rand`
4. **Key Validation**: Validate all incoming public keys
5. **Replay Protection**: Track and reject duplicate messages
6. **Forward Secrecy**: Ensure ratchet advances correctly
7. **Future Secrecy**: Ensure compromised keys don't affect future messages

---

## Estimated Total Timeline

| Milestone | Duration |
|-----------|----------|
| M1: Cryptographic Foundation | 1-2 weeks |
| M2: Key Management | 1-2 weeks |
| M3: X3DH Key Agreement | 1-2 weeks |
| M4: Double Ratchet | 2-3 weeks |
| M5: Session Management | 1-2 weeks |
| M6: Error Handling & Security | 1 week |
| M7: Testing & Documentation | 1-2 weeks |
| M8: Polish & Release | 1 week |
| **Total** | **9-15 weeks** |

---

## Success Criteria

1. All Signal Protocol test vectors pass
2. Complete conversation flows work correctly
3. Out-of-order message handling works
4. No memory leaks or safety issues
5. Performance meets targets (< 1ms per operation)
6. 80%+ code coverage
7. No issues found in 24-hour fuzz run
8. Documentation is complete and accurate
