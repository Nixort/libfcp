#!/usr/bin/env bash
# Copyright Nixort <https://github.com/Nixort> 2026.
#
# License: GNU General Public License v3.0 only.
# You can find the license file in the project root.
#
# Federated CFR Connect Protocol (FCP).
#
# Controlled non-production chaos scenarios. No scenario accepts credentials or a
# database URL as a command-line argument, and no scenario deletes infrastructure.

set -euo pipefail

: "${FCP_CHAOS_SCENARIO:?set service-restart, tunnel-restart or rds-multiaz-failover}"
: "${FCP_CHAOS_ENVIRONMENT:?set approved-nonproduction}"
: "${FCP_CHAOS_CHANGE_TICKET:?set an approved change-ticket identifier}"
: "${FCP_CHAOS_ACK:?set FCP_FABRIC_NONPRODUCTION_CHAOS_APPROVED}"

readonly FCP_CHAOS_SCENARIO FCP_CHAOS_ENVIRONMENT FCP_CHAOS_CHANGE_TICKET FCP_CHAOS_ACK
readonly FCP_CHAOS_PROBE_URL=${FCP_CHAOS_PROBE_URL:-http://127.0.0.1:8080/healthz}
readonly FCP_CHAOS_HOST=${FCP_CHAOS_HOST:-}
readonly FCP_CHAOS_RECOVERY_TIMEOUT_SECONDS=${FCP_CHAOS_RECOVERY_TIMEOUT_SECONDS:-300}

fail() {
    printf 'FCP Fabric chaos test refused: %s\n' "$1" >&2
    exit 64
}

[[ "$FCP_CHAOS_ENVIRONMENT" == approved-nonproduction ]] \
    || fail 'FCP_CHAOS_ENVIRONMENT must equal approved-nonproduction'
[[ "$FCP_CHAOS_ACK" == FCP_FABRIC_NONPRODUCTION_CHAOS_APPROVED ]] \
    || fail 'FCP_CHAOS_ACK must equal FCP_FABRIC_NONPRODUCTION_CHAOS_APPROVED'
[[ "$FCP_CHAOS_CHANGE_TICKET" =~ ^[A-Za-z0-9._-]{3,128}$ ]] \
    || fail 'FCP_CHAOS_CHANGE_TICKET must be a bounded identifier'
[[ "$FCP_CHAOS_PROBE_URL" =~ ^https?://[^[:space:]]+$ ]] \
    || fail 'FCP_CHAOS_PROBE_URL must be an HTTP(S) URL'
[[ "$FCP_CHAOS_RECOVERY_TIMEOUT_SECONDS" =~ ^[0-9]+$ ]] \
    && (( FCP_CHAOS_RECOVERY_TIMEOUT_SECONDS >= 10 && FCP_CHAOS_RECOVERY_TIMEOUT_SECONDS <= 1800 )) \
    || fail 'FCP_CHAOS_RECOVERY_TIMEOUT_SECONDS must be 10 through 1800'

probe_health() {
    local headers=()
    if [[ -n "$FCP_CHAOS_HOST" ]]; then
        [[ "$FCP_CHAOS_HOST" =~ ^[A-Za-z0-9.-]{1,253}$ ]] || fail 'FCP_CHAOS_HOST is malformed'
        headers+=(--header "Host: $FCP_CHAOS_HOST")
    fi
    curl --silent --show-error --fail --output /dev/null --write-out '%{http_code}' \
        --connect-timeout 2 --max-time 5 "${headers[@]}" "$FCP_CHAOS_PROBE_URL" | grep -qx '204'
}

wait_for_recovery() {
    local deadline=$(( $(date +%s) + FCP_CHAOS_RECOVERY_TIMEOUT_SECONDS ))
    until probe_health; do
        if (( $(date +%s) >= deadline )); then
            printf 'recovery timeout after %s seconds\n' "$FCP_CHAOS_RECOVERY_TIMEOUT_SECONDS" >&2
            return 1
        fi
        sleep 5
    done
}

run_systemd_restart() {
    local unit=$1
    command -v systemctl >/dev/null || fail 'systemctl is required for this scenario'
    [[ $EUID -eq 0 ]] || fail 'run service/tunnel chaos scenarios as root'
    systemctl is-active --quiet "$unit" || fail "$unit is not active"
    printf 'restarting %s for approved non-production chaos test ticket=%s\n' \
        "$unit" "$FCP_CHAOS_CHANGE_TICKET"
    systemctl restart "$unit"
    systemctl is-active --quiet "$unit" || fail "$unit did not return active"
    wait_for_recovery
}

run_rds_multiaz_failover() {
    : "${AWS_REGION:?set AWS_REGION}"
    : "${FCP_RDS_DRILL_IDENTIFIER:?set an approved disposable Multi-AZ drill identifier}"
    [[ "$FCP_RDS_DRILL_IDENTIFIER" == *drill* || "$FCP_RDS_DRILL_IDENTIFIER" == *chaos-test* ]] \
        || fail 'FCP_RDS_DRILL_IDENTIFIER must contain drill or chaos-test'
    command -v aws >/dev/null || fail 'AWS CLI is required for rds-multiaz-failover'
    aws rds describe-db-instances --region "$AWS_REGION" \
        --db-instance-identifier "$FCP_RDS_DRILL_IDENTIFIER" \
        --query 'DBInstances[0].MultiAZ' --output text | grep -qx 'True' \
        || fail 'target must be an existing Multi-AZ RDS drill instance'
    printf 'requesting managed Multi-AZ failover for %s ticket=%s\n' \
        "$FCP_RDS_DRILL_IDENTIFIER" "$FCP_CHAOS_CHANGE_TICKET"
    aws rds reboot-db-instance --region "$AWS_REGION" \
        --db-instance-identifier "$FCP_RDS_DRILL_IDENTIFIER" --force-failover
    aws rds wait db-instance-available --region "$AWS_REGION" \
        --db-instance-identifier "$FCP_RDS_DRILL_IDENTIFIER"
    wait_for_recovery
}

case "$FCP_CHAOS_SCENARIO" in
    service-restart)
        run_systemd_restart fcp-fabric.service
        ;;
    tunnel-restart)
        run_systemd_restart fcp-fabric-cloudflared.service
        ;;
    rds-multiaz-failover)
        run_rds_multiaz_failover
        ;;
    *)
        fail 'FCP_CHAOS_SCENARIO must be service-restart, tunnel-restart or rds-multiaz-failover'
        ;;
esac

printf 'controlled chaos scenario passed: %s\n' "$FCP_CHAOS_SCENARIO"
