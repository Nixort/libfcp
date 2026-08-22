# FCP Fabric: password, session и authenticator contract

## 1. Security objectives

The Fabric service authenticates a local account only to its home tenant. It never forwards a password, TOTP code, recovery code, browser session or refresh credential to a remote federation domain. A remote FCP Fabric domain conveys only a signed, action-scoped server assertion after it has authenticated its own user locally.

The implementation targets a strong practical baseline for self-hosted organizations: password plus TOTP for privileged roles, passkeys as a phishing-resistant local authentication option, short-lived sessions, durable revocation, non-enumerating errors, throttling and auditability. **TOTP is not phishing-resistant.** WebAuthn/passkey authentication is phishing-resistant only within its verified RP/origin model; FCP Fabric does not claim formal NIST assurance-level conformance without a complete control assessment.[5] [6]

## 2. Password lifecycle

| Property | Rule |
|---|---|
| Input | UTF-8, NFC normalization after well-defined input validation; permit password managers and paste |
| Minimum | 15 characters for password-only tenant policy; 8 characters only if tenant policy enforces MFA for that account |
| Maximum | At least 64 Unicode code points; set operational byte ceiling before KDF to prevent memory DoS, with documented client error |
| Composition | No arbitrary character-class rule and no periodic forced reset |
| Blocklist | Reject known-compromised/common passwords and tenant/context-derived values such as localpart/domain |
| KDF | Argon2id; PHC encoded version, per-record salt and calibrated parameters |
| Baseline calibration | Start with 19 MiB memory, 2 iterations, parallelism 1; benchmark in deployment and raise cost without creating KDF DoS |
| Pepper | Optional keyed prehash/HMAC managed outside database by KMS/HSM; pepper version is stored but secret is not |
| Error message | Same public failure for unknown account, suspended account and incorrect password |
| Migration | On successful login, rehash only when stored configuration is weaker than current policy |

The baseline parameters are a starting point rather than an eternal value. OWASP recommends Argon2id and identifies 19 MiB, two iterations and parallelism one as one minimum configuration; it also states that parameters should be calibrated for the deployment.[1] NIST specifies a password blocklist, throttling, password-manager support, no arbitrary composition rules, and storage resistant to offline attacks.[2]

### Password processing algorithm

```text
validate bounded UTF-8 input
  -> normalize NFC
  -> blocklist/context check
  -> HMAC(password, current_pepper) [only if configured]
  -> Argon2id(salted input, versioned parameters)
  -> store PHC verifier, algorithm parameters, pepper key version, changed_at
```

The server must use constant-time verification where library support provides it. It does one representative KDF calculation for nonexistent accounts to narrow timing differences. It must not log normalized password input, blocklist hit material or raw verifier values.

## 3. Login state machine

```text
anonymous
  -> password submitted
  -> [generic deny | throttled | password accepted]
  -> [MFA not enrolled: restricted setup session | MFA required: pending challenge | MFA policy allows: authenticated]
  -> authenticated session
  -> step-up pending for high-impact action
  -> revoked/expired
```

A password-accepted account with required MFA is **not** an authenticated session. It only receives a short-lived, single-purpose `LoginTransaction` cookie/token bound to the account, tenant, client and CSRF state. It can submit a TOTP response but cannot call generic user APIs. A bootstrap owner receives an even more restricted enrollment transaction that may only verify the first authenticator and establish the initial password profile; a public recovery-code issuance flow remains intentionally unavailable.

## 4. TOTP enrollment and verification

TOTP is based on RFC 6238: a unique randomly generated secret per factor, explicit time step and HMAC algorithm parameters. The specification describes a default 30-second step, recommends at most one accepted adjacent time step for latency, and states that a successfully used OTP must not be accepted a second time within its time step.[3]

| Stage | Required behavior |
|---|---|
| Start enrollment | Existing authenticated session plus recent password and existing MFA if one is active; bootstrap exception only once |
| Generate | CSPRNG secret; RFC 6238-compatible URI with issuer, canonical account address, algorithm, digits and period |
| Display | Provisioning URI/QR only once in the enrollment response; never in logs, audit data or subsequent GET response |
| Store pending | Envelope-encrypt seed with tenant/key version; store only ciphertext, nonce, wrapped key reference and metadata |
| Confirm | Verify a current code before setting factor `active`; atomically record that accepted moving step; no session is issued until confirmation succeeds. Transport-level rate limiting is still required before public deployment. |
| Verify active | 30-second steps, SHA-256 where authenticator compatibility supports it, 6–8 digits according to policy, current and at most prior step window; atomic record of accepted counter to prevent reuse |
| Reset/replace/disable | Step-up with a current existing factor or recovery process; apply delay/notification/audit; never accept an ordinary bearer session alone |
| Destroy | Cryptographically delete ciphertext/DEK reference, revoke recovery paths as policy dictates, retain redacted audit event |

The server decrypts a TOTP seed only in narrowly scoped verifier memory, zeroizes it through the chosen secret-memory facility where available, and never exposes the secret to database read APIs. Secret encryption uses AEAD with a unique nonce and authenticated context `(tenant_id, account_id, factor_id, version)` so a ciphertext cannot be swapped between tenants or factors.

## 5. WebAuthn/passkeys

FCP Fabric implements the safe `webauthn-rs` passkey ceremony flow for a single exact HTTPS RP origin. The policy requires a canonical RP domain equal to the origin host, root path, no origin credentials, no query/fragment, no explicit port, no subdomain relaxation and no any-port relaxation. The implementation uses the passkey flow with **required user verification** and does not enable user-presence-only, credential-internals, conditional UI or platform-specific workaround features.[5] [7]

| Stage | Required behavior |
|---|---|
| Self-enrollment begin | A verified local opaque access session plus session CSRF proof is required. Tenant/account/address and existing credential exclusions derive from server state; the client supplies no identity selector. |
| Registration state | The browser receives only a creation challenge plus Secure `__Host-` opaque ceremony and binding cookies. The complete challenge state and label are stored server-side in PostgreSQL. The registration handle is one-use, browser-bound and expires after five minutes. |
| Registration finish | The server atomically consumes ceremony state before verification, uses the library's safe registration verification, stores the serialized passkey and globally unique canonical credential ID, and writes redacted audit evidence. |
| Passwordless login begin | A canonical local address is accepted only for the deployment's RP tenant. Unknown, unavailable and non-enrolled accounts share generic denial. The server loads active passkeys and persists authentication state server-side. |
| Passwordless login finish | The server requires ceremony CSRF proof and opaque binding, consumes state once, validates the assertion, persists verified counter/backup-state changes, reconstructs current tenant-local authorization and issues normal opaque access/refresh sessions. |
| Counter semantics | Verification uses the library's assertion counter semantics. Any credential state returned after a verified assertion is persisted; counter behavior alone is not treated as a universal clone detector because syncable passkeys may not provide a meaningful counter. |

The `danger-allow-state-serialisation` crate feature is enabled **only** so its non-secret ceremony state can live in PostgreSQL behind a one-use opaque server handle. It is never serialized into a browser cookie, URL, response body, audit record or log. The upstream library explicitly warns that client-side ceremony state can undermine replay resistance.[5] [7]

## 6. Recovery codes

The recovery-code policy creates a fixed, policy-configurable inventory of ten 256-bit CSPRNG opaque values by default, rather than six-digit OTPs. The raw values are one-display-only and must never be emailed, logged or persisted. The database stores only a dedicated HMAC-derived fixed-width verifier for each value, its generation set ID and consumption timestamp. Replacing an inventory atomically invalidates the prior active set; a partial unique index allows only one active recovery-code set per account. Successful consumption is atomic and audited, while missing, invalidated, already consumed and cross-tenant verifiers share one false result.

A public recovery-code HTTP flow, notification, limited recovery session, forced factor re-enrollment, and rate limits are deliberately not implemented yet. Recovery-code generation, use, revocation and replacement remain high-risk audit actions and must be protected by step-up policy when exposed.

## 7. Session and token lifecycle

The service prefers opaque random credentials rather than putting mutable roles or long-term identity state into self-contained bearer JWTs. A 256-bit CSPRNG token is encoded base64url, transmitted only over TLS, and stored as a keyed digest/HMAC verifier rather than plaintext. Raw value is shown only at issuance.

| Credential | Audience | Lifetime | Storage/transport | Revocation |
|---|---|---:|---|---|
| Browser session/access | First-party Fabric UI/API | 15 minutes default | `Secure`, `HttpOnly` cookie; CSRF binding for state changes | Server record, account/session revoke |
| Refresh credential | First-party browser/native session | 30 days default; policy constrained | HttpOnly cookie or OS secure storage; never localStorage | One-time rotation, family revoke on reuse |
| Login transaction | MFA/challenge only | 5 minutes | HttpOnly, scope-limited cookie or opaque challenge handle | Single use/expiry |
| Step-up transaction | One high-risk action | 5 minutes | Bound to action, actor, tenant, session | Single use/expiry |

CLI/device login grants are not implemented; the `fcp-fabric` binary is restricted to offline migration and initial-tenant bootstrap. Every authenticated administration request resolves a separate short-lived opaque access credential against server-side access-session, family, account-state and current tenant-role records; browser claims are never authoritative. Deactivation, password change, MFA reset, role downgrade and security-event response must revoke relevant session families. Refresh rotation is implemented as one database transaction: the presented credential becomes consumed, its successor and new access session are inserted into the same family, and reuse of a consumed credential revokes the full family with a redacted audit event. Refresh transport returns the same public denial for reuse and other unavailable credentials, clears browser credentials, and rotates a separate session CSRF cookie on success. A tenant-scoped explicit family-revocation primitive is available to the authenticated administration layer.

For browser-facing applications, cookies are `Secure` and `HttpOnly`; SameSite policy is flow-specific and no state-changing request trusts SameSite alone. The service emits CSRF tokens bound to session for unsafe methods. For native/desktop clients, a future Fabric client flow should use authorization-code + PKCE with a loopback redirect or device authorization approach, not a user password passed to an arbitrary application. RFC 9700 recommends PKCE for public clients, exact redirect URI comparison, constraints/rotation for refresh tokens, scope/audience restriction, and expressly rejects the resource-owner-password credential grant.[4]

## 8. Authorization and step-up

The authenticator result only identifies an account. Permission is separately evaluated against current tenant-scoped role and policy. High-impact actions require a `StepUpGrant` bound to:

```text
tenant_id + account_id + session_id + action + target digest + issued_at + expires_at + nonce
```

The implemented role-change step-up binds an opaque five-minute grant to the authenticated tenant, actor, session family, exact target account, requested role, and grant/revoke intent. It cannot be replayed for another endpoint, another tenant, another administrator, a different session family, or a changed request body. The grant is atomically consumed before the role write and both issuance and consumption produce redacted audit events. The other listed high-impact operations require equivalent action-bound flows before they are exposed.

## 9. Abuse controls and observability

- Throttle by account, tenant and network/IP; distinguish hard lock from adaptive backoff to avoid attacker-induced permanent denial of service.
- Return generic login errors, but expose a user-safe retry delay when appropriate.
- Log redacted security events with correlation ID, tenant, account ID if known, result category, IP privacy policy, user-agent digest and factor type; never raw secrets.
- Alert users and tenant administrators on MFA disablement/replacement, password change, recovery use, session-family reuse and privileged role change.
- Apply rate/size limits to login, recovery, enrollment and federation endpoints before expensive Argon2 or decryption work.
- Support test clock and deterministic fake KMS only under explicit test feature; production has no development key fallback.

## References

[1] [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

[2] [NIST SP 800-63B — Authenticator and Verifier Requirements](https://pages.nist.gov/800-63-4/sp800-63b/authenticators/)

[3] [RFC 6238 — TOTP: Time-Based One-Time Password Algorithm](https://www.rfc-editor.org/rfc/rfc6238)

[4] [RFC 9700 — Best Current Practice for OAuth 2.0 Security](https://www.rfc-editor.org/rfc/rfc9700)

[5] [W3C Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/)

[6] [NIST SP 800-63B Revision 4](https://pages.nist.gov/800-63-4/sp800-63b.html)

[7] [`webauthn-rs` 0.5.4 documentation](https://docs.rs/webauthn-rs/0.5.4/webauthn_rs/)

[8] [OWASP Multifactor Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)
