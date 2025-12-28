# Test Vectors

Place deterministic Signal protocol test vectors here (e.g., official X3DH,
Double Ratchet, and Sesame examples). Keep files stable so integration tests
can load them directly.

## Libsignal generators

The Rust generators in `testing/vectors/libsignal/` are intended to be built
inside the libsignal repository (see `PLAN.md` for the pinned commit).

Regeneration steps:
1) Check out libsignal at the pinned commit.
2) Copy or symlink `testing/vectors/libsignal/gen_x3dh_vectors.rs` and
   `testing/vectors/libsignal/gen_ratchet_vectors.rs` into
   `libsignal/rust/protocol/src/bin/`.
3) Ensure `curve25519-dalek` is listed under `[dependencies]` in
   `libsignal/rust/protocol/Cargo.toml` (the generator uses it to derive the
   XEdDSA signing public key).
4) Run:
   - `cargo run --quiet --bin gen_x3dh_vectors > /path/to/signal/testing/vectors/x3dh_libsignal.json`
   - `cargo run --quiet --bin gen_ratchet_vectors > /path/to/signal/testing/vectors/ratchet_libsignal.json`

Alternatively, use the helper script from this repo:
`testing/vectors/libsignal/gen_vectors.sh /path/to/libsignal /path/to/signal`
