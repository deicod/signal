# Signal Protocol for Go

An implementation of the Signal Protocol in Go, structured as a reusable library for end-to-end encrypted messaging. The roadmap and detailed requirements live in `spec.md`.

## Compatibility
Wire compatibility is targeting Signal's Rust implementation (`libsignal`) at commit [`cfaf27f3a2d743e776ef553a770295d7e751277d`](https://github.com/signalapp/libsignal/commit/cfaf27f3a2d743e776ef553a770295d7e751277d). Work is in progress; the current internal envelope format will remain available as a legacy API via `signal.EnvelopeCipher` (see `PLAN.md`).

## Migration (Wire vs Legacy)
`signal.Cipher` produces libsignal wire ciphertexts. The legacy internal envelope remains available via `signal.EnvelopeCipher` (or `session.Cipher` with its `EncryptEnvelope`/`DecryptEnvelope` aliases). For mixed deployments, detect and route ciphertexts:

```go
switch signal.DetectCiphertextFormat(ct) {
case signal.CiphertextWire:
	plaintext, err = wireCipher.Decrypt(ct)
case signal.CiphertextEnvelope:
	plaintext, err = envelopeCipher.Decrypt(ct)
default:
	// unknown format
}
```

## Project Layout
- `crypto/` low-level primitives (Curve25519, AEAD, HKDF, HMAC, random)
- `keys/` identity, pre-key, signed pre-key, ephemeral key types
- `x3dh/` Extended Triple Diffie-Hellman handshake
- `ratchet/` Double Ratchet state transitions
- `session/` session orchestration across handshake and ratchet
- `protocol/` wire message definitions and serialization
- `store/` persistence interfaces with `store/memory/` for tests
- `errors/` typed errors
- `testing/` utilities and `testing/vectors/` for deterministic test data

## Getting Started
Prereqs: Go 1.25.4+. Clone the repo, then:

```bash
go build ./...
go test ./...
```

## Quick Start (1:1)
The high-level API is `signal.Cipher`, which produces/consumes opaque ciphertext bytes:

```go
package main

import (
	"fmt"

	"github.com/deicod/signal"
	"github.com/deicod/signal/store/memory"
)

func main() {
	aliceID, _ := signal.GenerateIdentityKeyPair()
	bobID, _ := signal.GenerateIdentityKeyPair()

	// Each side has its own ProtocolStore (memory store used here for brevity).
	aliceStore := memory.NewStore(aliceID, 1)
	bobStore := memory.NewStore(bobID, 2)

	// Bob publishes a pre-key bundle (signed pre-key + identity).
	signed, _ := signal.GenerateAndStoreSignedPreKey(bobStore, 1)
	kyber, _ := signal.GenerateAndStoreKyberPreKey(bobStore, 2)
	bundle, _ := signal.BuildPreKeyBundle(bobStore, 1, nil, signed.ID, &kyber.ID)

	aliceToBob := signal.NewCipher(aliceStore, signal.Address{Name: "bob", Device: 1})
	bobToAlice := signal.NewCipher(bobStore, signal.Address{Name: "alice", Device: 1})

	// First message bootstraps a session (X3DH + first Double Ratchet ciphertext).
	first, _ := aliceToBob.EncryptWithPreKeyBundle(bundle, []byte("hello"))
	plain, _ := bobToAlice.Decrypt(first)
	fmt.Println(string(plain)) // "hello"

	// Subsequent messages use the established session.
	next, _ := bobToAlice.Encrypt([]byte("pong"))
	plain, _ = aliceToBob.Decrypt(next)
	fmt.Println(string(plain)) // "pong"
}
```

## Quick Start (Groups: Sender Keys)
Signal group messaging uses Sender Keys: each sender generates a per-group sender key state and distributes it to every group member (typically via existing 1:1 sessions). After distribution, group messages use `signal.GroupCipher` with a simple `Encrypt/Decrypt([]byte)` API.

```go
groupID := "group-1"
aliceAddr := signal.Address{Name: "alice", Device: 1}

// State is stored per (group, sender).
name := signal.SenderKeyName{Group: groupID, Sender: aliceAddr}

// Sender creates a distribution message to share with the group.
dist, _ := signal.NewGroupSessionBuilder(aliceStore, name).Create()

// Each recipient processes the distribution message for this sender.
_ = signal.NewGroupSessionBuilder(bobStore, name).Process(dist)

aliceGroup := signal.NewGroupCipher(aliceStore, name)
bobFromAlice := signal.NewGroupCipher(bobStore, name)

ct, _ := aliceGroup.Encrypt([]byte("hello group"))
pt, _ := bobFromAlice.Decrypt(ct)
fmt.Println(string(pt)) // "hello group"

// When group membership changes, rotate and redistribute.
dist2, _ := signal.NewGroupSessionBuilder(aliceStore, name).Rotate()
_ = signal.NewGroupSessionBuilder(bobStore, name).Process(dist2)
```

## Quick Start (Multi-device: Sesame)
Use `signal.SesameConversation` to send to all non-stale devices for a user. You provide a roster provider that supplies device lists and pre-key bundles.

```go
type rosterProvider struct {
	devices []signal.SesameDevice
	bundles map[signal.Address]*signal.PreKeyBundle
}

func (p *rosterProvider) DeviceList(ctx context.Context, userID string) ([]signal.SesameDevice, error) {
	return p.devices, nil
}

func (p *rosterProvider) PreKeyBundle(ctx context.Context, addr signal.Address) (*signal.PreKeyBundle, error) {
	return p.bundles[addr], nil
}

provider := &rosterProvider{devices: devices, bundles: bundles}

conv := signal.NewSesameConversation(aliceStore, signal.Address{Name: "alice", Device: 1}, 24*time.Hour)
ciphertexts, _ := conv.EncryptWithRoster(context.Background(), "bob", []byte("hello"), provider, time.Now())
```

## Development
- Format before committing: `gofmt -w .` (or `goimports` if available).
- Lint: `golangci-lint run` (config in `.golangci.yml`).
- Vet: `go vet ./...`.
- Benchmarks: `go test -bench=. ./...`.

## CI
GitHub Actions runs on pushes and PRs:
- `golangci-lint run`
- `go vet ./...`
- `go build ./...`
- `go test ./...`

## Security Notes
- Use `crypto/rand` and constant-time comparisons for sensitive operations.
- Validate incoming public keys and avoid logging secrets.
- Zero sensitive buffers where practical and guard against replay/expiry in stores.
