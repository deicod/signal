# Repository Guidelines

## Project Structure & Module Organization
- Goal: a reusable Go implementation of the Signal protocol (see `spec.md` for roadmap and package breakdown).
- Keep to the planned layout: `crypto/` (primitives), `keys/`, `x3dh/`, `ratchet/`, `session/`, `protocol/`, `store/` (with `store/memory/` for tests), `errors/`, and `testing/` with `testing/vectors/`.
- Keep packages focused and acyclic; use interfaces in `store/` to isolate persistence. Add package docs in `doc.go`; keep public types small and cohesive.

## Build, Test, and Development Commands
- Format before committing: `gofmt -w .`; if `goimports` is available, run it too.
- Lint and vet (after adding `.golangci.yml`): `golangci-lint run` then `go vet ./...`.
- Quick sanity: `go build ./...`.
- Tests: `go test ./...`; disable cache with `go test -count=1 ./...`; benches live in `_test.go` and run via `go test -bench=. ./...`.

## Coding Style & Naming Conventions
- Go defaults: tabs, `gofmt`, exported symbols need doc comments, avoid stutter (`ratchet.Session` not `ratchet.RatchetSession`).
- Files and packages are lowercase; tests end with `_test.go`. Prefer table-driven tests and small functions.
- Return typed errors from `errors/`; avoid panics in library code. Use `context.Context` for anything that can block and `crypto/rand` plus constant-time comparisons.

## Testing Guidelines
- Tooling: standard `testing` plus `testify` assertions (per `spec.md`). Target ≥80% coverage and include edge cases (key validation, replay, out-of-order delivery).
- Keep deterministic vectors in `testing/vectors/` and load them in table-driven tests; check seeds/files in.
- Add integration suites for X3DH and Double Ratchet flows; fuzzing (`go test -fuzz=.`) is encouraged once helpers exist.

## Commit & Pull Request Guidelines
- History is minimal; use short imperative subjects (`Add curve25519 DH validation`) and keep subjects ≤72 characters. Add motivation in the body when non-trivial.
- In PRs, link the relevant `spec.md` task/milestone, list commands run, and call out new vectors or compatibility changes. Note any security-sensitive changes and update docs/tests alongside code.

## Security & Configuration Tips
- Zero sensitive buffers when feasible, guard against timing leaks with constant-time operations, and validate every public key.
- Stores must enforce freshness (signed pre-key expiry, session limits) and resist replay; avoid logging secrets. Favor dependency versions from `spec.md` and keep the Go toolchain ≥1.25.4 as in `go.mod`.
