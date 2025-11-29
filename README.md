# Signal Protocol for Go

An implementation of the Signal Protocol in Go, structured as a reusable library for end-to-end encrypted messaging. The roadmap and detailed requirements live in `spec.md`.

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
