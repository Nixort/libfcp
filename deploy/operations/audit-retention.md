# FCP Fabric audit-log retention

FCP Fabric writes security-relevant lifecycle events in PostgreSQL. The service does **not** implement an automatic `DELETE` job for `audit_events`: silent in-place deletion would weaken forensic integrity. Retention is therefore an operations control, not an application-side timer.

| Control | Required production policy |
|---|---|
| Primary PostgreSQL audit retention | Keep online audit rows for at least 400 days, unless a longer legal or contractual hold applies. |
| Immutable export | Export a daily ordered audit-event batch to a dedicated encrypted object store bucket with object lock / retention controls. |
| Export integrity | Store the date range, record count and SHA-256 of the canonical export manifest; alert on gaps or non-monotonic event time. |
| Access | Separate audit-reader role; no application runtime role may delete, alter or truncate audit records. |
| Deletion | A dual-approved, documented retention job may delete only exported, retention-expired data after legal-hold verification. |
| Recovery | Restore drills must verify audit continuity as well as tenant/account data. |

The production PostgreSQL role model must revoke `DELETE`, `TRUNCATE`, `ALTER` and ownership rights on `audit_events` from the Fabric application role. Export jobs require read-only credentials and must never include session token material, TOTP provisioning URI, password verifiers, raw recovery codes or browser cookies.

> Audit retention has legal and jurisdictional implications. The 400-day minimum is an operational baseline, not legal advice; the operator must set the final retention period with the responsible security and legal owners.
