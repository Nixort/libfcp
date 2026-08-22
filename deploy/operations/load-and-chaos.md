# FCP Fabric load and chaos validation

The scripts in `scripts/load/` and `scripts/chaos/` are deliberate **operators’ tools**, not continuous background jobs. They refuse to run unless an approved non-production environment label, change-ticket ID and exact acknowledgement are supplied. They send no authentication request, do not accept database URLs or credentials in arguments, do not delete infrastructure, and do not target a generic production endpoint.

| Validation | Script | Scope | Required evidence |
|---|---|---|---|
| Bounded availability baseline | `scripts/load/run_http_baseline.sh` | `GET /healthz` only; no identity or federation payload. | TSV with request status and timing, target/version, concurrency, request cap, error count and p50/p95/p99. |
| Fabric process restart | `scripts/chaos/run_controlled_chaos.sh` with `service-restart` | One approved non-production systemd deployment. | Alert fire/recovery, bounded readiness recovery time, redacted journal slice and post-recovery canary. |
| Tunnel connector restart | Same script with `tunnel-restart` | One approved non-production Cloudflare Tunnel connector. | Edge synthetic availability impact, tunnel state and recovery, canonical Host verification. |
| RDS Multi-AZ failover | Same script with `rds-multiaz-failover` | Existing Multi-AZ **drill** RDS instance whose name contains `drill` or `chaos-test`. | RDS event IDs, failover duration, application recovery timing, audit/session integrity checks. |

## Baseline procedure

First provision an isolated staging or restore-drill topology that matches the private RDS, loopback Fabric and managed edge model. Confirm observability and on-call alert routing before generating load. Use only a canonical host, a bounded request count and a concurrency compatible with the approved capacity plan.

```bash
export FCP_LOAD_TARGET='https://fabric.staging.example'
export FCP_LOAD_HOST='fabric.staging.example'
export FCP_LOAD_ENVIRONMENT='approved-nonproduction'
export FCP_LOAD_CHANGE_TICKET='CHG-1234'
export FCP_LOAD_ACK='FCP_FABRIC_NONPRODUCTION_LOAD_APPROVED'
export FCP_LOAD_REQUESTS=500
export FCP_LOAD_CONCURRENCY=10

./scripts/load/run_http_baseline.sh
```

The default baseline is intentionally modest. Increase volume only under an approved plan and monitor edge rate limiting, Fabric CPU/memory, connection-pool saturation, RDS connections/latency, KMS request errors/latency and alert delivery. A successful `/healthz` baseline is not a substitute for an authenticated end-to-end capacity test; it proves only that the public/loopback availability path remained responsive under the bounded test.

## Controlled chaos procedure

Run one scenario at a time, with an incident commander, a written rollback decision and a recovery-time budget. All scenarios require the environment guard below. The RDS scenario has an additional target-name and Multi-AZ check and never runs against an unnamed generic source database.

```bash
export FCP_CHAOS_ENVIRONMENT='approved-nonproduction'
export FCP_CHAOS_CHANGE_TICKET='CHG-1234'
export FCP_CHAOS_ACK='FCP_FABRIC_NONPRODUCTION_CHAOS_APPROVED'
export FCP_CHAOS_HOST='fabric.staging.example'
export FCP_CHAOS_PROBE_URL='https://fabric.staging.example/healthz'
export FCP_CHAOS_SCENARIO='service-restart'

sudo ./scripts/chaos/run_controlled_chaos.sh
```

For a disposable RDS Multi-AZ drill, configure `AWS_REGION` and an already-created `FCP_RDS_DRILL_IDENTIFIER` containing `drill` or `chaos-test`; use the identical guarded scenario. The operator must verify database application integrity and audit continuity after recovery. The script does not create, restore or delete the database; use the separately guarded restore drill to create a disposable target first.

## Acceptance criteria

Agree a recovery-time objective, error-budget allowance and load level before execution. The minimum evidence for production readiness is: an alert fires for the fault; all three recovery paths return green; no identity data or audit continuity is lost; no rate-limit/WAF bypass is added; an RDS failover is confined to a disposable Multi-AZ drill; and the ticket records observed versus target recovery time. Do not mark the production topology accepted from sandbox results or script contract tests alone.
