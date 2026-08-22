# FCP Fabric Service

`fcp-fabric-*` is the new **multi-tenant FCP Fabric platform** for FCP deployments. It separates local organization identity and administration from the portable FCP protocol core. A tenant owns a canonical domain, such as `parley.io`; a local account is a tenant-scoped name such as `benjamin@parley.io`; and a role attached to that account grants no privilege in `nextfcp.io`.

> The repository now includes a **runnable loopback-only Fabric service** with strict Host validation, request correlation, bounded request bodies, panic isolation and security headers. It activates opaque password-to-session routes when its complete login group is configured, and activates the complete TOTP/session/administration/WebAuthn route surface only when the complete `aws-kms` MFA group is also configured. The production provider envelope-encrypts TOTP data keys with AWS KMS; it resolves each historic reference from PostgreSQL and never persists plaintext DEKs. It is designed to sit behind a separately managed HTTPS edge and deliberately refuses direct public plaintext binds. It does **not yet provide a browser UI, OAuth/PKCE, email verification, a public recovery-code flow, TURN, or a complete end-user application**. Do not expose it directly to the Internet as a substitute for the required managed edge, database and operations controls.

## Architecture

| Crate | Responsibility | Does not own |
|---|---|---|
| `fcp-fabric-domain` | Canonical tenant domains, local addresses, lifecycle, roles, permission checks, invite/bootstrap policy, redacted audit types | SQL, HTTP, secrets, FCP private keys |
| `fcp-fabric-auth` | Argon2id verifier primitives, encrypted TOTP seed primitives, opaque token digests | Database connections, cookies, authorization decisions |
| `fcp-fabric-store` | PostgreSQL migrations and tenant-scoped transactions for accounts, roles, MFA factors, passkeys and one-use server-side ceremonies, paired sessions, explicit peer/key policy material, federation replay evidence and audit events | Raw passwords, raw tokens, raw TOTP seeds, browser-held WebAuthn state |
| `fcp-fabric-service` | Loopback-only Fabric process plus Host-guarded transport, opaque login transaction, AWS KMS envelope-key adapter, access/refresh session policy, strict WebAuthn/passkey ceremonies, TOTP step-up administration routes and hybrid-signed federation ingress | Direct public plaintext binding, automatic remote discovery or browser UI |
| `fcp-fabric` | Schema migration and **one-time** tenant bootstrap CLI | Password flags, raw signing-key flags, routine direct-DB administration |

The separation follows the central Matrix federation distinction: each Fabric domain authenticates its own local users, while another domain accepts only a fresh request signed by an explicitly trusted remote Fabric domain.[1] Passwords, TOTP values, passkey assertions and browser sessions are never federation credentials.

## Tenant and role scope

The initial roles are intentionally narrow. An `owner` can alter trust and administrator policy; an `admin` manages ordinary accounts but cannot silently enable a new federation peer; an `operator` publishes FCP bindings; an `auditor` reads redacted audit data; a `member` has only self-security and application permissions. Privileged role and federation-trust mutations require a separate step-up authentication result in the domain policy.

| Example | Interpretation |
|---|---|
| `benjamin@parley.io` | Local account at the `parley.io` Fabric domain; its roles are evaluated only within `parley.io`. |
| `alice@nextfcp.io` | A remote principal whose login is validated by `nextfcp.io`, not by `parley.io`. |
| `nextfcp.io` federation delivery | Requires local owner approval/pin, destination binding, fresh bounded lifetime, unique request ID and both mandatory FCP signatures. |

## Safe bootstrap

The only direct-database workflow is initial schema setup and tenant bootstrap. The connection URL is intentionally read **only** from `FCP_DATABASE_URL`; it is not accepted on the command line, preventing it from entering shell history or process argument listings.

```bash
export FCP_DATABASE_URL='postgres://fcp_bootstrap:…@db.example/fcp_fabric?sslmode=verify-full'

cargo +stable run -p fcp-fabric -- migrate
cargo +stable run -p fcp-fabric -- tenant bootstrap \
  --domain parley.io \
  --owner benjamin \
  --correlation-id bootstrap-parley-2026-08-22
```

Bootstrap creates `benjamin@parley.io` in `mfa_enrollment_required` state. It is deliberately not a normal active administrator until a password is set through an authenticated setup flow, a TOTP factor is encrypted and enrolled, and that factor is verified. The PostgreSQL deployment must be TLS-protected, backed up under an encrypted and tested recovery process, and accessible only to the Fabric service identity.

## Transport boundary

The process requires `FABRIC_PUBLIC_DOMAIN` and binds to `127.0.0.1:8080` by default. It rejects any non-loopback `FABRIC_BIND`, requiring a deployment-owned TLS reverse proxy or service mesh edge to terminate public HTTPS. Requests with another `Host` receive `421 Misdirected Request`; accepted responses receive `Cache-Control: no-store`, CSP, `nosniff`, `no-referrer`, cross-origin isolation headers and a validated/generated request identifier. CORS is not enabled by default. Set `FABRIC_ENABLE_HSTS=true` only after the entire configured domain is uniformly available over HTTPS.

```bash
FABRIC_PUBLIC_DOMAIN=parley.io \
  cargo +stable run -p fcp-fabric-service --bin fcp-fabric-service
```

To activate the password-stage browser route, configure **all four** of the following values or none of them: `FCP_DATABASE_URL`, `FABRIC_PASSWORD_DUMMY_VERIFIER`, `FABRIC_LOGIN_TRANSACTION_DIGEST_KEY`, and `FABRIC_LOGIN_BINDING_DIGEST_KEY`. The two digest values are independent 32-byte URL-safe, unpadded Base64 secrets supplied by the deployment secret manager; the verifier is a valid Argon2id PHC record used solely to equalize unknown-account timing. A partial configuration is rejected at startup. The database URL is read only from `FCP_DATABASE_URL`, never from arguments.

To activate the complete MFA/session router, build with `--features aws-kms` and configure **all six** MFA values or none of them: `FABRIC_TOTP_ACTIVE_KEY_REFERENCE`, `FABRIC_TOTP_ISSUER`, `FABRIC_SESSION_DIGEST_KEY`, `FABRIC_STEP_UP_DIGEST_KEY`, `FABRIC_WEBAUTHN_CEREMONY_DIGEST_KEY`, and `FABRIC_WEBAUTHN_BINDING_DIGEST_KEY`. The active reference identifies a ciphertext-only `aws_kms` envelope row provisioned in PostgreSQL; the process obtains AWS credentials and Region only through the standard AWS provider chain. The four digest keys must be independently generated 32-byte URL-safe unpadded Base64 values. The WebAuthn exact origin is deterministically `https://FABRIC_PUBLIC_DOMAIN/`; no origin override is accepted. If this group is configured in a binary without `aws-kms`, startup fails closed.

| Variable | Requirement and validated behavior |
|---|---|
| `FABRIC_PUBLIC_DOMAIN` | **Required.** Canonical Fabric domain accepted by the Host allowlist. |
| `FABRIC_BIND` | Optional; defaults to `127.0.0.1:8080`. It must be a valid loopback socket address; every public bind is rejected. |
| `FABRIC_ENABLE_HSTS` | Optional; only the exact value `true` enables one-year `includeSubDomains` HSTS. Enable only after HTTPS is uniformly available for the domain. |
| `FCP_DATABASE_URL` | Required for CLI migrations/bootstrap and for the executable password-login stage; it is environment-only. |
| `FABRIC_PASSWORD_DUMMY_VERIFIER` | Required with the login-stage group. Valid Argon2id PHC used for unknown-account timing equalization. |
| `FABRIC_LOGIN_TRANSACTION_DIGEST_KEY` | Required with the login-stage group. Independent unpadded URL-safe Base64 encoding of exactly 32 bytes. |
| `FABRIC_LOGIN_BINDING_DIGEST_KEY` | Required with the login-stage group. Independent unpadded URL-safe Base64 encoding of exactly 32 bytes. |
| `FABRIC_DATABASE_MAX_CONNECTIONS` | Optional when the login-stage group is enabled; defaults to `10` and must be an integer from `1` through `64`. |
| `FABRIC_TOTP_ACTIVE_KEY_REFERENCE` | Required with the complete MFA group. Opaque reference of a previously provisioned ciphertext-only AWS KMS data-key envelope. |
| `FABRIC_TOTP_ISSUER` | Required with the complete MFA group. Validated deployment-visible authenticator-app issuer; not a key or credential. |
| `FABRIC_SESSION_DIGEST_KEY` | Required with the complete MFA group. Dedicated 32-byte Base64url secret for refresh/access session digests. |
| `FABRIC_STEP_UP_DIGEST_KEY` | Required with the complete MFA group. Dedicated 32-byte Base64url secret for action-bound privileged grants. |
| `FABRIC_WEBAUTHN_CEREMONY_DIGEST_KEY` | Required with the complete MFA group. Dedicated 32-byte Base64url secret for server-side ceremony handles. |
| `FABRIC_WEBAUTHN_BINDING_DIGEST_KEY` | Required with the complete MFA group. Dedicated 32-byte Base64url secret for browser-binding handles. |
| `FCP_FABRIC_TEST_DATABASE_URL` | **Test-only.** Optional local disposable PostgreSQL URL for the real-store integration test. The test deliberately skips when unset and refuses a non-loopback host. Never set this to a production database. |

`POST /v1/login` accepts an address and password and returns the same `401 {"status":"denied"}` response for malformed addresses and invalid credentials. On an accepted password it returns no account, tenant, role, or next-stage data; instead it sets one-time `__Host-` Secure/HttpOnly transaction and browser-binding cookies and a short-lived non-HttpOnly CSRF cookie. The injectable full router also exposes `POST /v1/login/totp`, `POST /v1/login/session`, `POST /v1/login/enroll/totp/begin`, `POST /v1/login/enroll/totp/confirm`, `POST /v1/login/passkey/begin`, `POST /v1/login/passkey/finish`, `POST /v1/admin/passkeys/begin`, and `POST /v1/admin/passkeys/finish`. Password/TOTP transitions use their opaque transaction/binding cookies and matching `X-Fabric-CSRF`; passkey begin returns only a browser challenge plus three distinct five-minute opaque ceremony/binding/CSRF cookies, passkey login finish consumes its ceremony once. Passkey self-enrollment both begins and finishes only from a verified opaque access session plus session CSRF proof; completion additionally requires the separate WebAuthn ceremony CSRF proof and an exact server-side tenant/account match to the original ceremony. The TOTP route accepts only `{ "code": "…" }`, derives the tenant/account exclusively from the atomically consumed `mfa_challenge` transaction, then sets an opaque Secure/HttpOnly refresh cookie. The enrollment begin route consumes a bootstrap `mfa_enrollment` transaction, creates an encrypted pending factor, returns its sensitive `otpauth://` URI exactly once, and replaces the opaque transaction with a factor-bound confirmation transaction. Confirmation receives only `{ "code": "…" }`, atomically records its accepted time step during factor activation, and creates a session. The password-only route consumes only a `session_issuance` transaction and re-reads current account state and tenant-scoped roles before issuing the same refresh cookie. Completed sessions also receive a distinct 15-minute opaque access cookie; every administration request resolves it against current server-side family, account and role state, never browser claims. `POST /v1/admin/accounts/invite` allows only a tenant-local actor with `manage_accounts`; the requested localpart and initial least-privilege role remain policy-validated. `POST /v1/admin/accounts/{account_id}/roles/step-up` accepts a proposed role/grant-or-revoke operation plus fresh TOTP and returns only a five-minute Secure/HttpOnly one-use grant cookie. The subsequent role mutation consumes that grant only when its tenant, actor, session family, target account, role and grant intent all match; owner role changes remain outside this general workflow. All state-changing admin routes require the session CSRF proof. Cookies whose required path is `/` use the browser-enforced `__Host-` prefix (`Secure`, no `Domain`, `Path=/`); the deliberately admin-path-scoped step-up grant uses `__Secure-fabric-step-up`, because `__Host-` cookies cannot carry a narrower path. All browser cookies use `SameSite=Strict`; every cookie-backed state-changing route also requires the matching `X-Fabric-CSRF` proof. The runnable process activates the complete MFA/router surface only under the all-or-nothing `aws-kms` group above; its provider resolves the active and historic envelope references with AWS KMS and fails closed if KMS is unavailable.

## Security boundary

Password handling uses an Argon2id PHC verifier with per-record salt and a configurable compromised-password blocklist interface. The initial password-only baseline is 15 characters and Argon2id at 19 MiB, two iterations and parallelism one; operators must calibrate and raise cost within availability budgets.[2] TOTP uses a random per-factor seed, an RFC 6238-compatible 30-second profile, envelope encryption with tenant/account/factor associated data, and atomic storage of the accepted moving time step to prevent re-use.[3]

TOTP is supported because authenticator applications are often operationally useful; it is **not phishing-resistant**. The injectable full router supplies a strict WebAuthn/passkey path before phishing-resistant authentication is described: its RP domain equals the exact HTTPS origin host, no explicit port/subdomain/any-port relaxation is permitted, user verification is required, and ceremony state is PostgreSQL-held behind one-use opaque browser-bound handles. This supports phishing resistance within the WebAuthn RP/origin model; it is not a formal NIST assurance-level certification.[4] [6]

Opaque refresh credentials are 256-bit random values. The Fabric store retains only an HMAC-derived digest and a session-family record; raw credentials are delivered once through a Secure/HttpOnly cookie or an OS-protected native credential store. Each active family also carries a separate 15-minute opaque access credential whose digest is checked with current account, role and family revocation state on every authenticated administration request. `POST /v1/session/refresh` requires a separate session CSRF cookie, atomically consumes the presented credential, stores its successor within the same family, and replaces both cookies. Re-presenting a consumed credential revokes the full family and receives the same generic public denial as other unavailable credentials; a tenant-scoped explicit family-revocation primitive is available for later authenticated administration. Recovery inventories use separate HMAC digest-key material, consist of ten 256-bit opaque values by default, are one-display-only, invalidate the previous active set atomically, and consume each verifier once.[5]

## Federation boundary

The server policy implements a bounded `FederationDelivery` record. It binds the declared source/destination domains, `sender@source`, `recipient@destination`, request ID, issue/expiry timestamps and payload into one canonical transcript. The `PUT /v1/federation/deliver/{request_id}` boundary requires the path ID to equal the signed body ID, decodes only fixed-width Base64url Ed25519/ML-DSA-65 identity and signature fields, and verifies both mandatory FCP signatures. It accepts no browser cookie, password, user session or remote user-controlled tenant selector.

Ingress uses `PostgresFederationPeerPolicyResolver`, which resolves only a tenant-owner-persisted local/remote domain peer, current non-retired JSON key document, and expected fingerprint. It does not query remote DNS, fetch remote keys, or auto-trust key rotation. After policy admission, the store atomically inserts `(tenant, peer, request_id)` and a SHA-256 digest of the exact canonical signed transcript; duplicate IDs return `409` and never receive a second admission/audit event. A `202` is **durable security admission only**, not proof that the opaque application payload was dispatched or delivered. Application inbox/outbox dispatch remains a separate transactional follow-on. The repository does not claim open federation, arbitrary remote discovery or automatic remote-key changes; the architecture uses explicit mutual trust and owner-approved remote key pinning.

## Release documentation

| Need | Document |
|---|---|
| Deployment topology and threat model | [`architecture.md`](architecture.md) |
| Relational model, tenant policy and federation state | [`domain-model.md`](domain-model.md) |
| Password, MFA, passkey, session and recovery contract | [`authentication.md`](authentication.md) |
| Managed edge and AWS KMS implementation sources | [`edge-and-kms-sources.md`](edge-and-kms-sources.md) |
| Isolated AWS staging topology and activation sequence | [`../../deploy/topology/aws-staging/README.md`](../../deploy/topology/aws-staging/README.md) |
| Prometheus/Blackbox availability probes and alerts | [`../../deploy/observability/README.md`](../../deploy/observability/README.md) |
| Audit retention and secret rotation operations | [`../../deploy/operations/audit-retention.md`](../../deploy/operations/audit-retention.md) and [`../../deploy/secrets/README.md`](../../deploy/secrets/README.md) |
| Incident response and controlled validation | [`../../deploy/operations/incident-response.md`](../../deploy/operations/incident-response.md) and [`../../deploy/operations/load-and-chaos.md`](../../deploy/operations/load-and-chaos.md) |

## References

[1] [Matrix Specification — Server-Server API](https://spec.matrix.org/latest/server-server-api/)

[2] [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

[3] [RFC 6238 — TOTP: Time-Based One-Time Password Algorithm](https://www.rfc-editor.org/rfc/rfc6238)

[4] [NIST SP 800-63B — Authenticator and Verifier Requirements](https://pages.nist.gov/800-63-4/sp800-63b/authenticators/)

[5] [RFC 9700 — Best Current Practice for OAuth 2.0 Security](https://www.rfc-editor.org/rfc/rfc9700)

[6] [W3C Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/)
