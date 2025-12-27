• Added a Sesame conversation usage example and README quick‑start so the new multi‑device API is easy to discover and copy. The
  example shows a roster provider + bootstrap flow, and the README now has a Sesame section right after Sender Keys.

  - New ExampleSesameConversation plus a tiny roster provider in example_test.go to demonstrate encrypting to two devices and
    decrypting on each.
  - New “Quick Start (Multi-device: Sesame)” section in README.md with a minimal provider snippet and SesameConversation call.

  Tests: go test ./...

  If you want me to keep going, pick one:

  1. Add a multi‑user send helper that wraps repeated EncryptWithRoster calls (self + multiple recipients).
  2. Extend the roster provider to model server accept/reject flows (old/new device lists) more explicitly.
  3. Implement optional Sesame features (retry requests + session expiration).
