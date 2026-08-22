# FCP operations

FCP has two intentionally different control-plane layers. `libfcp-server` remains an **embedded signed configuration authority** for applications that already own admission policy. The `fcp-fabric-*` crates provide a multi-tenant persistence, authentication and federation-policy platform with a loopback-only service intended to sit behind a managed TLS edge. Neither layer is a WebRTC relay, TURN server or CFR participant.

## Embedded configuration authority

`libfcp-server` holds one complete authority signing identity, one federation namespace and one monotonically increasing configuration snapshot. Its integrating control plane owns member admission, key protection, durable epoch storage and distribution of signed `FCFG` configuration bytes.

| Rule | Reason |
|---|---|
| Protect both Ed25519 and ML-DSA-65 authority private keys outside source control and process arguments. | The complete identity can sign a replacement configuration. |
| Pin the complete public authority identity through authenticated out-of-band distribution. | Carrier delivery remains untrusted. |
| Persist a strictly monotonic configuration epoch. | Members reject stale snapshots. |
| Audit configuration epoch, member-set digest and operator action. | Rollback, removal and admission decisions remain explainable. |
| Run STUN/TURN and signaling independently. | The authority does not relay WebRTC or CFR media/control traffic. |

The configuration lifecycle remains unchanged: choose a stable `FederationId`, admit a verified CFR-to-complete-FCP binding, call `replace_members(next_epoch, members)`, call `publish()`, distribute canonical signed bytes, and durably persist the new epoch before treating the policy as active.

## Multi-tenant FCP Fabric platform

The `fcp-fabric-*` workspace adds an implementation base for a domain such as `parley.io`. It stores tenant-local accounts such as `benjamin@parley.io`, roles, Argon2id PHC verifiers, encrypted TOTP factors, opaque refresh-token digests, redacted audit events and explicit remote federation trust state in PostgreSQL. Each row and command carries a tenant scope; roles never cross domains.

> Fabric exposes a loopback-only Axum service; deploy it only behind the managed TLS edge described in [`fabric/README.md`](fabric/README.md). Do not expose a public plaintext listener or claim SSO, email confirmation, public registration, unrestricted open federation or formal phishing-resistant assurance. Passkeys are supported for the exact configured origin; TOTP is not phishing-resistant.

Detailed deployment boundaries, threat model and implementation status are maintained in the [FCP Fabric deployment guide](fabric/README.md).

## Bootstrap CLI

`FCP Fabric CLI` replaces the former blanket “no CLI” rule only for two narrow, safer offline operations:

1. `FCP Fabric CLI migrate` applies the embedded PostgreSQL migration plan.
2. `FCP Fabric CLI tenant bootstrap` creates the first organization and owner in `mfa_enrollment_required` state.

The database URL is read exclusively from `FCP_DATABASE_URL`; it is not a command argument. The CLI has no password argument, raw authority private-key argument, arbitrary member-list argument or routine direct-DB administrative subcommand. After bootstrap, ordinary account, role, trust and federation actions use authenticated Fabric service workflows.

```bash
export FCP_DATABASE_URL='postgres://fcp_bootstrap:…@db.example/fcp_fabric?sslmode=verify-full'

cargo +stable run -p fcp-fabric -- migrate
cargo +stable run -p fcp-fabric -- tenant bootstrap \
  --domain parley.io \
  --owner benjamin \
  --correlation-id bootstrap-parley-2026-08-22
```

## Production deployment prerequisites

A public deployment requires a dedicated persistent environment: private PostgreSQL Multi-AZ with encrypted backup/restore verification, AWS KMS or an equivalent external key manager for TOTP data-key envelopes, managed TLS termination, rate limiting/WAF, secret rotation, private monitoring/alerts, time synchronization, structured redacted logs and incident-response procedures. The default development sandbox and a local test database do not satisfy those requirements.

Password/TOTP and federation design rationale, including Matrix-style domain trust, are documented with primary references in [`docs/fabric/architecture.md`](fabric/architecture.md) and [`docs/fabric/authentication.md`](fabric/authentication.md).
