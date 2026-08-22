# Contributing to libfcp

FCP is a protocol boundary. A change must preserve canonical wire behavior,
explicit trust separation, bounded remote input and portability of
`libfcp-core`. Do not merge a behavior change merely because it compiles on the
concrete WebRTC.rs adapter.

## Repository map

| path | responsibility |
|---|---|
| `crates/libfcp-core/` | FCP grammar, complete endpoint identities, mandatory dual signatures, signed configuration, connection state and bounded replay. |
| `crates/libfcp/` | Primary member SDK, CFR binding policy, directory, routing and adapter contract. |
| `crates/libfcp-server/` | In-process signed configuration authority. |
| `crates/libfcp-webrtc/` | Optional Rust/Tokio WebRTC.rs adapter and live localhost integration tests. |
| `docs/` | Canonical protocol, security, integration and authority-operation documentation. |
| `assets/` | Rendered architecture documentation image. |
| `.github/workflows/` | CI, supply-chain checks and protected manual release workflow. |

## Support policy

`libfcp-core`, `libfcp` and `libfcp-server` support Rust **1.85**. The optional
`libfcp-webrtc` package requires Rust **1.98+** because of the selected
WebRTC.rs dependency graph. Keep concrete-engine dependencies out of the
portable crates.

## Required checks

```bash
# Portable protocol, SDK and authority.
cargo +1.85.0 fmt --all -- --check
cargo +1.85.0 test --workspace --exclude libfcp-webrtc --locked
cargo +1.85.0 clippy --workspace --exclude libfcp-webrtc --all-targets --locked -- -D warnings
cargo +1.85.0 check -p libfcp-core --no-default-features --locked --target aarch64-linux-android
cargo +1.85.0 check -p libfcp-core --no-default-features --locked --target aarch64-apple-ios
cargo +1.85.0 check -p libfcp-core --no-default-features --locked --target wasm32-unknown-unknown

# Concrete engine.
cargo +stable test -p libfcp-webrtc --tests --locked -- --nocapture
cargo +stable clippy -p libfcp-webrtc --all-targets --locked -- -D warnings

# Supply-chain policy when cargo-deny is installed.
cargo +stable deny check all
```

## Change rules

Every Rust source, example and test file carries the project GPL header. New
public APIs require docs; the workspace denies missing public documentation and
unsafe code. A parser or wire-format change requires hostile-input coverage and
canonical round-trip coverage. A state-machine or adapter change requires a
negative transition test. A change to the concrete engine must retain the real
localhost ICE → DTLS → SCTP → DataChannel test.

Do not add a signaling service, account system, raw-key CLI, hidden CFR identity
mapping or unbounded remote queue to this repository. Those are deployment
concerns or would violate the explicit protocol boundary documented in
[`docs/security.md`](docs/security.md).
