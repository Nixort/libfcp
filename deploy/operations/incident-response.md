# FCP Fabric incident-response runbook

This runbook applies to the loopback Fabric process, its managed TLS edge, AWS KMS TOTP envelopes, PostgreSQL HA/backup controls, and the availability/audit observability boundary. The incident commander owns prioritisation and external communications; responders preserve evidence and avoid speculative changes. Do not put passwords, TOTP codes, provisioning URIs, raw recovery codes, cookies, bearer tokens, database URLs, AWS credentials or Cloudflare credentials in tickets, chat, logs or alert annotations.

| First action for every incident | Required result |
|---|---|
| Open an incident record and assign an incident commander. | A unique incident/change reference, severity, start time and accountable owner. |
| Preserve immutable evidence before remediation. | Redacted logs, metrics time window, deployment version, Cloudflare event IDs, AWS event IDs and request correlation IDs. |
| Establish the scope using tenant-safe aggregates. | Affected component, domains/counts and time range; no end-user secret material. |
| Use a canary first. | One instance/one controlled path is verified before fleet-wide change. |
| Record a recovery decision and a follow-up owner. | Clear rollback, customer notice and post-incident actions. |

## Service unavailable

**Trigger:** `FcpFabricLivenessFailed`, `FcpFabricReadinessFailed`, a failed synthetic probe or authenticated service symptoms.

1. Confirm the alert from a second management path. Capture the probe target, response class, incident start time and deployment version.
2. On the affected host, inspect only structured service health: `systemctl status fcp-fabric`, the redacted journal slice, listener state on `127.0.0.1:8080`, and `curl` probes with the canonical `Host` header. Do not use a public plaintext bind as a diagnostic workaround.
3. Verify the process configuration file was validated as root, the systemd hardening unit is unchanged, and the database/KMS provider status is healthy before restarting.
4. Restart one Fabric instance. Verify `/healthz`, `/readyz`, a generic login denial and a non-sensitive authenticated canary. If it recovers, roll remaining instances within the approved change window; otherwise stop and escalate to the implicated dependency runbook.
5. Resolve only after liveness and readiness remain green for 15 minutes and the root cause, rollback state and customer impact are recorded.

## AWS KMS unavailable or TOTP envelope decrypt failure

**Trigger:** TOTP completion/enrollment infrastructure errors, KMS CloudTrail error, KMS health alarm or a sudden increase in generic MFA failure after a deployment.

1. Freeze TOTP key rotation and do not delete, disable or replace an envelope row. Preserve the opaque reference, KMS request/event IDs and deployment revision; never export plaintext DEKs.
2. Verify the workload identity, Region, KMS key state, `kms:Decrypt` permission and encryption-context values. The context must exactly bind `fcp-fabric-purpose=totp-data-key/v1` and the stored opaque reference; do not bypass it.
3. Test a single known non-production/canary factor referencing both an old and the active envelope. If only the active reference fails, revert `FABRIC_TOTP_ACTIVE_KEY_REFERENCE` to the previous approved reference and roll the service. This affects only future enrollment; it does not change historic factors.
4. If compromise is suspected, follow the TOTP rotation sequence in `deploy/secrets/README.md`, preserve old decrypt access for historic factors, and require a security-approved factor migration plan. Do not claim rotation complete until old and new reference acceptance evidence exists.
5. Escalate to AWS support/security if KMS key state, policy or regional control-plane availability is the cause. Close only after both old/new canaries and normal enrollment completion are confirmed.

## Suspected account compromise or refresh-token reuse

**Trigger:** session-family reuse detection, anomalous privileged mutation, user report, credential-stuffing alert or unexpected passkey/TOTP changes.

1. Treat the account as potentially compromised. Preserve correlation IDs, family ID, timestamps, role-change audit events and relevant redacted edge telemetry. Do not expose raw credentials or security-factor values.
2. Revoke the affected tenant-local session family through the approved administrative control, or rotate the dedicated session digest key only when a global sign-out is approved. Refresh-token reuse already revokes its family atomically; verify this in persistent state.
3. Disable/lock the affected account according to local policy, review tenant-local role changes and federation peer changes, and require fresh local authentication before recovery. Roles never transfer to other Fabric domains.
4. Review passkey and TOTP factor changes. Preserve factor IDs and key references; do not delete forensic records. Enroll replacement factors only after user identity recovery is verified.
5. Notify the customer/security owner through the approved channel, document scope and decide whether breach-reporting obligations apply with legal counsel.

## Edge WAF false positive, DDoS or TLS/Tunnel outage

**Trigger:** managed edge availability alarm, sudden `403`/challenge increase, Cloudflare Tunnel disconnect, traffic spike or certificate/TLS failure.

1. Determine whether the Fabric loopback health probe is green. A green loopback probe with public failures confines the incident to edge/DNS/TLS/Tunnel policy rather than the application.
2. Export protected edge analytics/event IDs and configuration version. Keep login/refresh/enrollment rate limits enabled during investigation; do not disable host validation or expose `127.0.0.1:8080` publicly.
3. For a confirmed false positive, create the narrowest temporary exception for the affected route/source and expiry. Use observe/log mode first for managed WAF tuning; obtain incident commander approval before a blocking-rule change.
4. For attack traffic, keep managed DDoS/TLS controls active, tighten the existing bounded login/session route rule if necessary, and coordinate with the edge provider. Do not move user authentication to another unverified hostname.
5. Verify canonical-host rejection, HTTPS certificate chain, tunnel origin Host header, rate limits and public synthetic probes after recovery. Remove temporary exception rules and attach a post-change export to the incident.

## PostgreSQL Multi-AZ failover, backup or PITR drill failure

**Trigger:** RDS event, database connection errors, backup/PITR alarm, restore drill mismatch, replication/storage alert or application readiness degradation tied to database operations.

1. Preserve RDS event IDs, CloudWatch database metrics, SQL error category and recent deployment version. Do not alter the source database or automatically delete a restore target.
2. Confirm that the DB is private, encrypted, Multi-AZ and accepts traffic only from the Fabric application security group. Check whether a planned maintenance/failover is already in progress.
3. For an availability event, allow managed failover to complete, let connection retries settle, and use a single canary process before rolling restarts. Do not fail open around session/MFA persistence.
4. For recovery assurance, use `deploy/postgres/scripts/restore_drill_aws.sh` against a named disposable drill target. Perform read-only schema/migration/audit-continuity integrity checks and retain evidence. Delete the drill target only after explicit approval.
5. If point-in-time recovery cannot meet the target, declare the recovery objective unmet, preserve evidence and escalate to the database/security owners. Record data-gap, audit-gap and customer-impact assessment.

## Audit pipeline or retention failure

**Trigger:** missing daily immutable export, checksum/count mismatch, retention-job exception, audit reader access anomaly, or restored audit continuity failure.

1. Stop destructive retention actions immediately. The application must not silently purge `audit_events`; preserve the current database state and export job logs.
2. Compare PostgreSQL time range/counts with the immutable export manifest. Record only manifest hash, range and counts in the ticket. Verify object-lock/retention policy and encryption are active.
3. If an export is missing, create a backfill from read-only access, generate a new manifest, mark it as a backfill and retain the original gap evidence. Never overwrite an immutable manifest.
4. If unauthorized modification is suspected, remove application-role access, rotate affected credentials, snapshot forensic evidence under approval and escalate to security/legal. Restore write access only after role grants are re-reviewed.
5. Reconcile the audit ledger before closing: online retention, immutable export, checksum/count continuity, legal-hold state and restore-drill evidence must all be documented.

## Monitoring blindness

**Trigger:** `FcpFabricProbeTargetMissing`, Alertmanager delivery failure, missing logs or inability to verify alert routing.

1. Declare monitoring degraded even if service health looks normal. Use an independent approved path for current service/edge/database checks.
2. Verify Prometheus target discovery, Blackbox exporter availability, canonical Host template, private network reachability, rule-file load and Alertmanager route. Do not expose monitoring endpoints publicly to simplify debugging.
3. Test the full alert lifecycle with a controlled canary outage: firing, delivery, acknowledgement and resolution. Ensure alert payload has no identifiers or secret values.
4. Backfill missing metrics/log intervals only when integrity can be proven; otherwise mark the coverage gap explicitly in the incident and recovery report.
5. Close after monitoring remains healthy for 24 hours or the approved service-level window, with a recorded root cause and recurrence prevention.

## Breach-response escalation

If evidence indicates disclosure of passwords, TOTP seed material, session tokens, private keys, KMS credentials, Cloudflare credentials, database backups or significant audit tampering, stop routine remediation and invoke the organisation’s breach response process. Preserve evidence, restrict access, rotate the specific compromised secret domains according to `deploy/secrets/README.md`, assess legal notification duties with counsel and coordinate public communication through authorised leadership only.
