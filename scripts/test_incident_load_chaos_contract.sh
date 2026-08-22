#!/usr/bin/env bash
# Copyright Nixort <https://github.com/Nixort> 2026.
#
# License: GNU General Public License v3.0 only.
# You can find the license file in the project root.
#
# Federated CFR Connect Protocol (FCP).

set -euo pipefail

readonly ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
readonly RUNBOOK="$ROOT/deploy/operations/incident-response.md"
readonly LOAD_GUIDE="$ROOT/deploy/operations/load-and-chaos.md"
readonly LOAD_SCRIPT="$ROOT/scripts/load/run_http_baseline.sh"
readonly CHAOS_SCRIPT="$ROOT/scripts/chaos/run_controlled_chaos.sh"

fail() {
    printf 'incident/load/chaos contract failed: %s\n' "$1" >&2
    exit 1
}

require() {
    local pattern=$1
    local file=$2
    grep -Fq -- "$pattern" "$file" || fail "missing $pattern in ${file#$ROOT/}"
}

for file in "$RUNBOOK" "$LOAD_GUIDE" "$LOAD_SCRIPT" "$CHAOS_SCRIPT"; do
    [[ -f "$file" ]] || fail "missing required asset ${file#$ROOT/}"
done

require 'AWS KMS unavailable or TOTP envelope decrypt failure' "$RUNBOOK"
require 'Suspected account compromise or refresh-token reuse' "$RUNBOOK"
require 'Edge WAF false positive, DDoS or TLS/Tunnel outage' "$RUNBOOK"
require 'PostgreSQL Multi-AZ failover, backup or PITR drill failure' "$RUNBOOK"
require 'Audit pipeline or retention failure' "$RUNBOOK"
require 'Monitoring blindness' "$RUNBOOK"
require 'Breach-response escalation' "$RUNBOOK"
require 'FCP_FABRIC_NONPRODUCTION_LOAD_APPROVED' "$LOAD_SCRIPT"
require 'FCP_FABRIC_NONPRODUCTION_CHAOS_APPROVED' "$CHAOS_SCRIPT"
require 'rds-multiaz-failover' "$CHAOS_SCRIPT"
require 'FCP_RDS_DRILL_IDENTIFIER must contain drill or chaos-test' "$CHAOS_SCRIPT"
require 'do not delete infrastructure' "$LOAD_GUIDE"
require 'not a substitute for an authenticated end-to-end capacity test' "$LOAD_GUIDE"

bash -n "$LOAD_SCRIPT"
bash -n "$CHAOS_SCRIPT"

if FCP_LOAD_TARGET='http://127.0.0.1:1' \
    FCP_LOAD_HOST='fabric.test' \
    FCP_LOAD_ENVIRONMENT='production' \
    FCP_LOAD_CHANGE_TICKET='CHG-TEST' \
    FCP_LOAD_ACK='FCP_FABRIC_NONPRODUCTION_LOAD_APPROVED' \
    "$LOAD_SCRIPT" >/dev/null 2>&1; then
    fail 'load script accepted a production environment label'
fi

if FCP_CHAOS_SCENARIO='service-restart' \
    FCP_CHAOS_ENVIRONMENT='production' \
    FCP_CHAOS_CHANGE_TICKET='CHG-TEST' \
    FCP_CHAOS_ACK='FCP_FABRIC_NONPRODUCTION_CHAOS_APPROVED' \
    "$CHAOS_SCRIPT" >/dev/null 2>&1; then
    fail 'chaos script accepted a production environment label'
fi

printf 'incident/load/chaos contract passed.\n'
