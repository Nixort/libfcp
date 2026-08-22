# FCP Fabric: доменная модель и federation trust

## 1. Нормативные инварианты

1. **Tenant boundary precedes every decision.** Любая сущность, доступная пользователю, принадлежит ровно одному `tenant_id`; все query/mutation ports требуют tenant scope, а не получают его из необязательного caller input.
2. **Human identity is local.** `benjamin@parley.io` означает localpart `benjamin` в tenant, чей canonical domain равен `parley.io`. Это не RFC 5322 email и не proof of mailbox ownership; email, если нужен, хранится отдельным verified contact.
3. **Roles are tenant-local.** Permission evaluates `(actor_id, tenant_id, role, action, target)`; remote user principals cannot be assigned local roles by federation input.
4. **Federation identities are domains, not users.** `nextfcp.io` maps to a trusted remote authority document plus a locally approved policy. Federation input cannot alter account roles, password credentials, MFA factors or local authority keys.
5. **No confused deputy.** Domain and recipient must be canonicalized before signature verification and bound into the signed request; a valid request for `parley.io` is invalid for any other local tenant.
6. **Every privilege mutation is auditable.** A durable audit event shares the transaction with the state change. Secret material is redacted before the audit boundary.

## 2. Domain types

```text
TenantId             UUIDv7 / UUID; immutable primary identity
DomainName           lower-case UTS #46 / IDNA processed DNS domain, no port
AccountId            UUIDv7 / UUID; immutable principal identity
Localpart            Unicode-normalized, restricted display/login component
UserAddress          Localpart + "@" + DomainName; canonical tenant-scoped login identifier
Role                 Owner | Admin | Operator | Auditor | Member
Permission           typed capability, never a raw string accepted from client
AuthorityKeyId       opaque rotation identifier
RemoteServerId       UUID; local record for an approved remote DomainName
TrustState           Pending | Active | Suspended | Revoked
FederationRequestId  128-bit random identifier, uniqueness retained through replay window
PolicyVersion        monotonic unsigned integer per tenant
AuditEventId         UUIDv7 / UUID
```

`UserAddress` parsing is performed exactly once in the domain layer. It rejects missing/duplicate `@`, empty parts, noncanonical domain encoding, unsupported localpart normalization, and a domain that does not match the selected tenant. Presentation uses a canonical value, while account lookup uses tenant ID plus normalized localpart; no cross-tenant global `username` lookup exists.

## 3. Database ownership model

| Table | Key constraints | Sensitive fields | Tenant boundary |
|---|---|---|---|
| `tenants` | `id`, unique `canonical_domain` | none | root |
| `tenant_domains` | unique active domain, tenant FK | verified delegation metadata | domain to tenant |
| `accounts` | unique `(tenant_id, normalized_localpart)` | password verifier reference only | tenant |
| `account_roles` | unique `(tenant_id, account_id, role)` | none | tenant |
| `password_credentials` | one active record per account | Argon2id PHC verifier, parameter metadata | account's tenant |
| `mfa_totp_factors` | account FK, active factor states | envelope-encrypted seed, key version, encrypted provisioning metadata | account's tenant |
| `recovery_code_verifiers` | per account, consumed timestamp | slow hash / verifier only | account's tenant |
| `sessions` | opaque ID hash, account FK, family FK | token verifier/digest, device hash, expiry | account's tenant |
| `refresh_token_families` | family ID, account FK | revocation metadata | account's tenant |
| `federation_peers` | unique `(tenant_id, remote_domain)` | approved public key document fingerprint | tenant |
| `federation_keys` | peer FK + key ID, expiry | remote public keys only | tenant |
| `federation_replays` | unique `(tenant_id, remote_peer_id, request_id)` | body digest, expiration | tenant |
| `federation_outbox` | event/order id | signed payload/metadata, retry state | tenant |
| `audit_events` | immutable event ID and tenant sequence | **never** passwords/tokens/seeds | tenant |

Row-level security may be enabled as defence in depth in PostgreSQL, but application-level tenant predicates and independently tested repository ports remain mandatory. A connection pool must never reuse a request-local tenant context as an implicit authorization proof.

## 4. Role policy matrix

| Action | Owner | Admin | Operator | Auditor | Member |
|---|---:|---:|---:|---:|---:|
| Manage tenant domain | yes + step-up | no | no | no | no |
| Manage administrator role | yes + step-up | no | no | no | no |
| Create/invite member | yes | yes | no | no | no |
| Suspend/revoke ordinary member session | yes | yes | no | no | self only |
| Publish local FCP member configuration | yes | yes | yes | no | own request only |
| Change federation trust/remote key | yes + step-up | no | no | no | no |
| View audit records | yes | constrained | constrained | yes | self events only |
| Enroll/disable own MFA | yes + step-up | yes + step-up | yes + step-up | yes + step-up | yes + step-up |

The final implementation should encode this in a single policy engine with typed actions. Route handlers and CLI subcommands only map requests into an `AuthorizationContext`; they must not duplicate `if role == ...` decisions.

## 5. Account lifecycle

```text
bootstrap owner
  -> invited / active account
  -> password set
  -> MFA pending enrollment
  -> MFA active
  -> suspended (sessions revoked; federation authority assertions prohibited)
  -> deactivated (immutable audit retained; reusable name policy explicitly decided)
```

A tenant bootstrap creates one `owner` in `mfa_pending`; the account may obtain a restricted setup session only for MFA enrollment, recovery-code issuance and initial profile completion. It is not allowed to create other privileged accounts or enable federation until its MFA factor has been verified. There must always be at least one active owner with a usable privileged factor.

Public registration is deliberately **not** the first default. Phase one implements `invite-only` tenant admission. The tenant can later elect self-registration through an explicit policy and verified-contact workflow; that transition requires threat-model review, anti-automation controls and email verification design.

## 6. Federation peer lifecycle

```text
not configured
  -> pending(remote domain + expected fingerprint)
  -> challenge verified / administrator approval
  -> active
  -> suspended (deny all new delivery, retain evidence)
  -> revoked (deny; keys retained only under defined evidence retention policy)
```

An owner seeds a `pending` peer with a remote domain and expected public-key document fingerprint acquired out of band. The authority resolves the declared endpoint under SSRF controls, fetches and independently verifies the key document, then requires owner step-up confirmation before `active`. Any unexpected active-key transition re-enters `pending` rather than silently accepting a new remote identity.

Active peer rules: signed federation requests must match the exact remote domain and an active known key, use the key within its validity, include a unique request ID, fall within clock skew and retention windows, target the local tenant domain, and pass action-level federation policy. The `federation_replays` insert is atomic with delivery acceptance, so concurrent duplicate requests cannot both succeed.

## 7. Authority configuration relationship

`FederationMember` in the existing FCP configuration remains a cryptographic binding between CFR identity and FCP endpoint identity. It does not become an account record. A local member account may own zero or more endpoint-binding records; account authorization controls whether the authority will publish/revoke those bindings. This preserves the protocol core's portability and avoids treating a device key as a human identity.

## 8. Rust ports to implement

```rust
pub trait TenantRepository {
    fn tenant_by_domain(&self, domain: &DomainName) -> Result<Tenant, StoreError>;
    fn create_bootstrap(&self, request: BootstrapTenant) -> Result<BootstrapResult, StoreError>;
}

pub trait AccountRepository {
    fn account_by_login(
        &self,
        tenant: TenantId,
        localpart: &NormalizedLocalpart,
    ) -> Result<Option<Account>, StoreError>;
    fn apply_account_change(&self, change: AccountChange) -> Result<AuditEvent, StoreError>;
}

pub trait FederationPeerRepository {
    fn peer_for_domain(
        &self,
        tenant: TenantId,
        remote: &DomainName,
    ) -> Result<Option<FederationPeer>, StoreError>;
    fn accept_once(
        &self,
        accepted: AcceptedFederationRequest,
    ) -> Result<Acceptance, StoreError>;
}
```

Production ports will be asynchronous; the example is intentionally abbreviated to emphasize typing and ownership. `accept_once` must perform peer-state/key/expiry/replay persistence in a single database transaction, never as a read-then-write sequence.
