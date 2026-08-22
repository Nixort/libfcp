# FCP Fabric observability

Fabric emits JSON structured logs through `tracing` and exposes two intentionally small loopback probes. `GET /healthz` returns `204` when the process can serve HTTP; `GET /readyz` returns a non-sensitive transport readiness object. Neither endpoint reports tenant names, accounts, session state, KMS references, database URLs, credentials, passkeys, TOTP metadata or audit contents. Both still pass through canonical Host validation and security-response middleware.

| Asset | Purpose | Exposure boundary |
|---|---|---|
| `prometheus/blackbox.yml.template` | Defines HTTP liveness/readiness modules with the canonical Host value. | Blackbox exporter on the same protected host/network namespace as Fabric. |
| `prometheus/prometheus.yml.template` | Scrapes only `127.0.0.1:8080` through Blackbox exporter on `127.0.0.1:9115`. | Prometheus must not be publicly exposed. |
| `prometheus/fcp-fabric-alerts.yml` | Pages on persistent probe failures or loss of the monitoring target. | Alertmanager routing is operator-owned; labels intentionally exclude identities and secrets. |

## Installation boundary

Copy the templates to a protected Prometheus/Blackbox deployment, replace `<FABRIC_PUBLIC_DOMAIN>` with the canonical public domain, and bind both monitoring services to a private management network or loopback only. Configure Blackbox exporter to listen on `127.0.0.1:9115` and ensure its HTTP client reaches Fabric on `127.0.0.1:8080`. The `Host` header must equal `FABRIC_PUBLIC_DOMAIN`; a mismatched header correctly produces `421` and will make the probe fail.

The supplied probes validate **process/HTTP availability only**. They do not prove PostgreSQL reachability, AWS KMS availability, Cloudflare edge behavior, database failover or audit-export completion. Those dependencies require separate provider-native checks and the controlled topology drills in the operations runbooks.

## Alert handling and log policy

Route `severity=page` to the on-call channel with a link to `deploy/operations/incident-response.md`; do not send raw HTTP headers, request bodies or JSON logs to a public webhook. Store structured service logs in an encrypted, access-controlled system with a documented retention policy. Before external log shipping, apply an allowlist that retains timestamp, severity, request correlation ID, route template, response class and operational error category while removing `Cookie`, `Set-Cookie`, `Authorization`, request body, database URL, provisioning URI and credential fields.

A production acceptance must show a successful liveness/readiness probe, a deliberate stop/restart alert, a recovery alert resolution, and an on-call route that receives no PII or secret values. The templates are local deployment contracts; they do not constitute a live monitoring deployment in this sandbox.
