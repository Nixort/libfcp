# FCP Fabric Service: архитектурная база

**Статус:** проектная спецификация для первой реализации.

**Область:** multi-tenant Fabric service, административный CLI, локальные учётные записи и междоменная federation.

**Не является:** заменой `libfcp-core`, готовой compliance-сертификацией или обещанием, что TOTP защищает от phishing.

## 1. Решение по границам продукта

FCP будет состоять из трёх намеренно разделённых уровней. `libfcp-core` остаётся переносимой библиотекой wire-format и peer connection state; в ней не должно быть пользователей, паролей, SQL, HTTP, cookies или административных полномочий. Новый **Fabric service** отвечает за организации, учётные записи, роли, federation trust, конфигурацию FCP-участников и audit trail. Отдельный `FCP Fabric CLI` является операторским клиентом, а не скрытым обходом серверной авторизации.

| Уровень | Ответственность | Не должен делать |
|---|---|---|
| `libfcp-core` | Signed FCP configuration/envelopes, endpoint identities, state machine | Хранить пользователей, принимать пароль, выполнять HTTP или SQL |
| `fcp-fabric-domain` | Typed policy и инварианты tenant/account/role/federation | Знать детали PostgreSQL, Axum, cookies или KMS SDK |
| `fcp-fabric-store` | Transactions, migrations, tenant-scoped storage и durable audit outbox | Принимать авторизационные решения без domain layer |
| `fcp-fabric-auth` | Password verification, MFA, sessions, recovery, throttling interfaces | Давать доступ к чужому tenant или выпускать federation signing keys |
| `fcp-fabric-service` | HTTPS API, middleware, federation endpoints, metrics | Прямо читать master secrets из CLI flags |
| `FCP Fabric CLI` | Offline migration and one-time initial tenant bootstrap | Модифицировать production DB напрямую или заменять authenticated service workflows |

Пользователь `benjamin@parley.io` — это локальный principal с неизменяемым внутренним UUID и отображаемым адресом `<localpart>@<tenant-domain>`. Его роль действует исключительно в tenant `parley.io`; наличие такого имени не предоставляет ему прав в `nextfcp.io`.

## 2. Предлагаемая production топология

```text
                         ┌─────────────────────────────┐
                         │ parley.io DNS + TLS endpoint │
                         └──────────────┬──────────────┘
                                        │ HTTPS
             ┌──────────────────────────▼──────────────────────────┐
             │ fcp-fabric-service: parley.io                     │
             │ local API · local login · public domain keys · S2S   │
             └───────┬───────────────────────┬─────────────────────┘
                     │                       │
       encrypted secret refs                  │ signed HTTPS federation
                     │                       │ request + TLS
              ┌──────▼──────┐       ┌────────▼───────────┐
              │ KMS/HSM or  │       │ nextfcp.io authority │
              │ dev keyring │       └─────────────────────┘
              └─────────────┘
                     │
              ┌──────▼────────────────────────────────────┐
              │ PostgreSQL                                 │
              │ tenants · accounts · roles · sessions      │
              │ MFA verifier/ciphertext · audit · keys     │
              └───────────────────────────────────────────┘
```

Первая production-конфигурация использует PostgreSQL, TLS termination с корректно переданным trusted proxy context и отдельно управляемый KMS/HSM либо secret manager. SQLite может быть допустим **только** для test/development profile: его нельзя описывать как эквивалент production multi-instance deployment. Для реального постоянного service требуется durable external storage и секреты; default sandbox не является production hosting environment.

## 3. Trust domains

### 3.1 Локальный пользователь и tenant

`parley.io` является tenant и federation domain. Authority сначала проверяет локальную authentication state пользователя; затем проверяет локальное role/policy decision. Никакой входящий federation request не может создать local admin role, изменить membership или заменить authentication factor пользователя.

### 3.2 Удалённый домен

Для `alice@nextfcp.io` принимающий `parley.io` authority доверяет не паролю Alice, а **подписанному request от `nextfcp.io` authority**. Получатель независимо проверяет TLS, destination/domain binding, remote published key document, key identity, expiry, request timestamp, nonce/request ID, canonical body digest, signature и локальную allow/deny policy. Это следует модели Matrix, где server-to-server requests используют HTTPS и request-level public-key signatures, а published server keys имеют ограниченную validity и rotation semantics.[1]

### 3.3 Ключи и discovery

Вместо копирования всех Matrix endpoints FCP будет иметь малую поверхность:

| Endpoint | Назначение | Authentication |
|---|---|---|
| `GET /.well-known/fcp/server` | Опциональная domain delegation | TLS; строгий redirect/cache/SSRF policy |
| `GET /_fcp/federation/v1/version` | Объявление совместимой реализации | Public |
| `GET /_fcp/key/v1/server` | Expiring authority key document | Public, self-signed hybrid identity |
| `PUT /_fcp/federation/v1/send/{request_id}` | Bounded signed server-to-server delivery | TLS + canonical FCP federation signature |

Key document содержит domain, key id, public hybrid identity, `valid_until`, previous verification keys с expiry, canonical signatures и cache policy. Key rotation создаёт новый active key, но не уничтожает historical verification key до окончания necessary evidence window. Direct discovery выполняется с SSRF protection: запрет loopback/link-local/private адресов, allowlisted schemes/ports, лимиты DNS results, redirect count, response sizes и timeouts. DNS никогда не является самостоятельным trust anchor; TLS certificate связан с исходным domain identity, как в Matrix discovery model.[1]

### 3.4 Federation mode

В первой реализации используется **explicit mutual trust**, а не anonymous open federation. Tenant administrator предлагает domain, получает fingerprint/verification key document через безопасный out-of-band channel, и разрешает policy. После этого server-to-server requests могут быть приняты. Это уменьшает риск SSRF, spam, impersonation и accidental cross-tenant data exposure. Позже можно реализовать open federation как явный product mode с отдельными abuse controls, не как тихий default.

## 4. Threat model and mandatory controls

| Угроза | Обязательный контроль |
|---|---|
| Credential stuffing и online password guessing | Per-account, per-IP и tenant rate limit; generic failures; Argon2id; breached-password blocklist; audit alert |
| Offline DB theft | Argon2id with per-record salt + calibrated params; optional server-side pepper outside DB; encrypted TOTP seed; no raw session/refresh token at rest |
| Session/refresh theft | Short-lived opaque access/session, rotating single-use refresh records, reuse detection and family revocation; device/session-bound record; server-side logout/revocation |
| CSRF/XSS token exfiltration | HttpOnly/Secure cookies, SameSite policy, CSRF token for state changes, strict CORS, CSP at UI boundary; CLI uses loopback or device authorization rather than password handoff |
| MFA-factor takeover | Current factor plus reauthentication/step-up to enroll/disable/reset factor; out-of-band notification; recovery codes only once; audit event |
| Tenant boundary bypass/IDOR | Every storage operation has tenant ID predicate; actor/tenant authorization centralized in domain policy; unguessable internal IDs alone are insufficient |
| Malicious remote domain / replay | TLS, signed canonical request, domain/destination/audience binding, nonce/request-id store, timestamp and expiry window, rate limits, allowlist policy |
| Key substitution/rotation attack | Published signed key document, short validity cap, key ID, old-key expiry, explicit admin approval for initial domain trust and unexpected key transition |
| Privileged abuse | Separate owner/admin/auditor roles, least privilege, MFA mandatory for privileged roles, append-only audit events, dual-control later for key rotation and cross-domain trust changes |
| SSRF via discovery | Egress allow policy, resolved-IP validation on every redirect/connection, DNS rebinding defense, bounded redirect/DNS/body/time limits |

## 5. Authentication posture

Passwords are a local tenant identity mechanism, not a federation credential. The service uses Argon2id with versioned parameters, per-password random salt, bounded maximum input, and a password blocklist. OWASP recommends Argon2id and a memory-hard work factor; its published baseline includes 19 MiB, two iterations and one degree of parallelism, but the exact production value must be calibrated under load.[2] NIST recommends at least 15 characters for password-only login, or at least eight when the password is one factor in MFA, accepts password managers and warns against arbitrary composition rules.[5]

TOTP is required for the requested authenticator-app support and mandatory for authority owners and tenant administrators. It yields an AAL2-like two-factor arrangement when combined with a password, but it is not phishing-resistant. FCP will therefore make WebAuthn/passkeys a first-class follow-on authenticator interface. NIST requires a phishing-resistant option at AAL2 for systems that claim that assurance level.[4] FCP does **not** claim formal NIST AAL compliance without a full external control assessment.

## 6. Roles and high-impact actions

| Role | Scope | Capabilities |
|---|---|---|
| `owner` | One tenant | Domain settings, administrators, federation trust, retention policy, authority-key rotation approval |
| `admin` | One tenant | Invite/register accounts, manage members, force session revocation, configure allowed federation peers |
| `operator` | One tenant | Publish FCP member configuration and view operational health; no account/role/MFA reset rights |
| `auditor` | One tenant | Read immutable audit events and federation decisions; no mutations |
| `member` | Self | Sign in, manage own device/MFA/recovery codes, use permitted FCP application functions |

A role grant never crosses domains. The only cross-domain statement is an authority-signed claim that a local principal is permitted by its own authority to take a narrowly scoped federation action. Receiving authority policy still controls whether that action is accepted.

## 7. Audit and lifecycle invariants

Every mutating request must produce an immutable audit event containing an event ID, tenant, actor type/ID, request/correlation ID, action, target, resulting policy version, timestamp and a redacted metadata digest. Passwords, raw tokens, TOTP seeds, recovery codes, private keys and encrypted secret plaintext must never be recorded in audit logs. Audit writes occur in the same database transaction as the mutation or through a durable transactional outbox.

High-impact operations require step-up MFA: adding/removing privileged role, changing password, enrolling/disabling/replacing MFA, creating recovery codes, rotating authority keys, enabling federation, modifying federation allowlist, and deleting tenant. At least one owner with a usable privileged authenticator must remain after any role or factor change.

## 8. Explicit non-goals for first implementation

The first implementation will not promise end-to-end message encryption, user identity proofing, universal interoperability with Matrix, unrestricted anonymous public registration, SSO/SAML/SCIM, or a self-hosted KMS. It will implement a secure foundation and interfaces for these; claims beyond that require separate design, integration and review.

## References

[1] [Matrix Specification — Server-Server API](https://spec.matrix.org/latest/server-server-api/)

[2] [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

[3] [OWASP Multifactor Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)

[4] [NIST SP 800-63B, Digital Identity Guidelines](https://pages.nist.gov/800-63-4/sp800-63b.html)

[5] [NIST SP 800-63B, Authenticator and Verifier Requirements](https://pages.nist.gov/800-63-4/sp800-63b/authenticators/)

[6] [RFC 9700 — Best Current Practice for OAuth 2.0 Security](https://www.rfc-editor.org/rfc/rfc9700)
