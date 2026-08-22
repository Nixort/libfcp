# FCP security boundary

FCP is a connection-control and routing layer for CFR. It authenticates canonical protocol messages, constrains how a selected WebRTC adapter reaches an established control channel, and binds every accepted remote message to a complete endpoint identity. It does **not** convert an endpoint identity into a person, user account, domain, device-attestation claim, or CFR identity by implication.

Read this document before deployment. The normative grammar and state machine are in [`protocol.md`](protocol.md); the multi-tenant FCP Fabric platform, password/MFA/session contract and managed-edge deployment boundary are described in [`fabric/README.md`](fabric/README.md). This document states the remaining deployment obligations and non-guarantees.

## Trust model

| Object | FCP verifies | Application must establish |
|---|---|---|
| Federation authority identity | The signed `FCFG` snapshot matches the out-of-band pinned Ed25519 **and** ML-DSA-65 authority keys. | How a member received and authenticated the authority identity. |
| Configuration snapshot | Canonical encoding, both signatures, federation ID, unique bounded bindings, and strictly newer epoch. | Admission, revocation workflow, availability, and retention. |
| Endpoint identity | The sender controls the corresponding Ed25519 and ML-DSA-65 signing keys for one envelope. | The relationship among a user, device, endpoint, and CFR participant key. |
| Signaling carrier | Nothing merely by transport; signed FCP bytes verify locally. | Confidentiality, delivery, ordering, retry, rate limits, and availability. |
| WebRTC peer transport | The adapter reports a connected ordered reliable control channel. | STUN/TURN policy, certificate/fingerprint UX, NAT reachability, and engine correctness. |
| CFR payload | Exact bytes reach an explicit established FCP binding. | CFR membership, key agreement, repair, media protection, and application semantics. |
| FCP Fabric platform | Tenant-scoped domain/account/role policy, Argon2id verification, KMS-envelope encrypted TOTP factors, opaque rotating sessions with reuse revocation, passkeys, signed remote delivery and redacted audit state. | Live cloud acceptance for the managed edge, KMS, PostgreSQL recovery, monitoring and incident operations. |

## FCP guarantees

Every configuration and envelope has exactly one accepted dual-signature encoding. Ed25519 and ML-DSA-65 authenticate the same canonical bytes, including federation ID, attempt ID, complete sender identity, complete recipient identity, and the kind-specific body. A record missing either signature is invalid; there is no single-signature or prior-format fallback.

`decode_verified` validates the bounded wire grammar and both signatures before it returns a variable body. The connection state machine rejects a wrong federation, recipient, sender identity, attempt, invalid transition, and duplicate replay outside its fixed FIFO window. Candidate messages bind to their parent offer or answer digest. `CfrControl` reaches application routing only after the adapter reports that the fixed FCP channel is connected.

Configuration is an explicit signed record, not discovery. A member accepts only a newer epoch from its pinned complete authority identity and confirms that its own CFR identity and exact local endpoint identity appear in the snapshot. FCP never infers a CFR identity from endpoint bytes.

## Post-quantum boundary

FCP uses **hybrid authentication** at its configuration and signaling boundaries: both Ed25519 and ML-DSA-65 verification must succeed. ML-DSA-65 is the FIPS 204 parameter set intended to provide NIST security category 3; its public keys are 1,952 bytes and signatures are 3,309 bytes.[1]

The Rust implementation uses RustCrypto `ml-dsa` 0.1.1. This dependency is not independently audited by this project. It is a release-candidate dependency choice, not a claim of completed third-party assurance. Operators must maintain dependency monitoring, reproduce the locked build, and apply their own supply-chain review before production deployment.[2]

> The WebRTC **DTLS, SCTP, and SRTP path is not post-quantum**. FCP’s hybrid signatures authenticate the FCP configuration and signaling boundaries only; the selected WebRTC engine still determines the algorithms and properties of the live transport handshake and media path.

## Explicit non-guarantees

The portable FCP protocol core does not provide a signaling server, TURN service, certificate UI, device attestation, traffic-analysis protection, offline delivery, automatic glare resolution, or a complete federation-membership product policy. FCP Fabric provides a loopback-only service intended to sit behind a separately managed TLS edge; it must never be exposed through a public plaintext bind. The platform does not provide a user-facing application, email/invite delivery, public registration, unrestricted open federation, automatic remote discovery, or an external security audit. A malicious carrier can drop, delay, reorder, replay, or observe signaling metadata. A WebRTC path can fail because of NAT topology or engine/platform behavior.

The first release candidate rejects a simultaneous conflicting offer while a local offer is active and reports `Glare`; it does not silently choose a “polite” peer. The application must define any retry or role-selection policy.

## Deployment rules

Bootstrap the complete Fabric federation identity through an authenticated out-of-band mechanism. For the FCP Fabric platform, use TLS-protected PostgreSQL, a KMS/HSM or external secret manager, audited migrations, tenant-scoped database access, NTP-synchronized clocks and a tested restore procedure. `FCP Fabric CLI` accepts its connection URL only through `FCP_DATABASE_URL`; it has no password or key flags. Carry signaling over a transport whose confidentiality and availability properties match the product threat model. Configure application-approved STUN/TURN servers for public networks; `SessionConfig::loopback()` is local-test-only. Bound application event and signaling processing time, drain adapter output regularly, and impose product-level connection timeouts.

For normal termination, call `WebRtcRsSession::begin_close(CloseCode)` and deliver its signed envelope through the application signaling carrier before forcefully closing the local engine. A verified remote close is surfaced as `SessionEvent::Closed { reason }`; an engine or control-channel failure is `SessionEvent::Failed`.

## Reporting vulnerabilities

Do not open a public issue for a suspected confidentiality, authentication, replay, parser, or memory-exhaustion vulnerability. Follow [`../SECURITY.md`](../SECURITY.md) for private reporting instructions.

## References

[1] [FIPS 204 — Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final).

[2] [RustCrypto ML-DSA repository](https://github.com/RustCrypto/signatures/tree/master/ml-dsa).

[3] [RFC 8831 — WebRTC Data Channels](https://datatracker.ietf.org/doc/html/rfc8831).

[4] [RFC 8445 — Interactive Connectivity Establishment](https://www.rfc-editor.org/rfc/rfc8445.html).

[5] [CFR security boundary](https://github.com/Nixort/cfr_protocol/blob/main/docs/security.md).

[6] [FCP Fabric platform deployment and implementation status](fabric/README.md).
