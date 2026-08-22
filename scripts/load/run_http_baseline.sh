#!/usr/bin/env bash
# Copyright Nixort <https://github.com/Nixort> 2026.
#
# License: GNU General Public License v3.0 only.
# You can find the license file in the project root.
#
# Federated CFR Connect Protocol (FCP).
#
# Bounded availability-only load test. It must never target production.

set -euo pipefail

: "${FCP_LOAD_TARGET:?set an approved non-production base URL, without a path}"
: "${FCP_LOAD_HOST:?set the canonical Fabric Host header}"
: "${FCP_LOAD_ENVIRONMENT:?set approved-nonproduction}"
: "${FCP_LOAD_CHANGE_TICKET:?set an approved change-ticket identifier}"
: "${FCP_LOAD_ACK:?set FCP_FABRIC_NONPRODUCTION_LOAD_APPROVED}"

readonly FCP_LOAD_TARGET FCP_LOAD_HOST FCP_LOAD_ENVIRONMENT FCP_LOAD_CHANGE_TICKET FCP_LOAD_ACK
readonly REQUESTS=${FCP_LOAD_REQUESTS:-500}
readonly CONCURRENCY=${FCP_LOAD_CONCURRENCY:-10}
readonly CONNECT_TIMEOUT_SECONDS=${FCP_LOAD_CONNECT_TIMEOUT_SECONDS:-2}
readonly MAX_TIME_SECONDS=${FCP_LOAD_MAX_TIME_SECONDS:-5}
readonly RESULT_DIR=${FCP_LOAD_RESULT_DIR:-"$(pwd)/fcp-fabric-load-results"}

fail() {
    printf 'FCP Fabric load test refused: %s\n' "$1" >&2
    exit 64
}

[[ "$FCP_LOAD_ENVIRONMENT" == approved-nonproduction ]] \
    || fail 'FCP_LOAD_ENVIRONMENT must equal approved-nonproduction'
[[ "$FCP_LOAD_ACK" == FCP_FABRIC_NONPRODUCTION_LOAD_APPROVED ]] \
    || fail 'FCP_LOAD_ACK must equal FCP_FABRIC_NONPRODUCTION_LOAD_APPROVED'
[[ "$FCP_LOAD_CHANGE_TICKET" =~ ^[A-Za-z0-9._-]{3,128}$ ]] \
    || fail 'FCP_LOAD_CHANGE_TICKET must be a bounded identifier'
[[ "$FCP_LOAD_TARGET" =~ ^https?://[^/?#]+$ ]] \
    || fail 'FCP_LOAD_TARGET must be an http(s) base URL without path, query or fragment'
[[ "$FCP_LOAD_HOST" =~ ^[A-Za-z0-9.-]{1,253}$ ]] \
    || fail 'FCP_LOAD_HOST must be a canonical hostname'
[[ "$REQUESTS" =~ ^[0-9]+$ ]] && (( REQUESTS >= 1 && REQUESTS <= 50000 )) \
    || fail 'FCP_LOAD_REQUESTS must be 1 through 50000'
[[ "$CONCURRENCY" =~ ^[0-9]+$ ]] && (( CONCURRENCY >= 1 && CONCURRENCY <= 100 )) \
    || fail 'FCP_LOAD_CONCURRENCY must be 1 through 100'
[[ "$CONNECT_TIMEOUT_SECONDS" =~ ^[0-9]+$ ]] && (( CONNECT_TIMEOUT_SECONDS >= 1 && CONNECT_TIMEOUT_SECONDS <= 10 )) \
    || fail 'FCP_LOAD_CONNECT_TIMEOUT_SECONDS must be 1 through 10'
[[ "$MAX_TIME_SECONDS" =~ ^[0-9]+$ ]] && (( MAX_TIME_SECONDS >= 1 && MAX_TIME_SECONDS <= 30 )) \
    || fail 'FCP_LOAD_MAX_TIME_SECONDS must be 1 through 30'

mkdir -p "$RESULT_DIR"
[[ -d "$RESULT_DIR" ]] || fail 'FCP_LOAD_RESULT_DIR cannot be created'

readonly started_epoch=$(date -u +%s)
readonly work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

probe() {
    local number=$1
    local output="$work_dir/$number"
    local curl_result
    curl_result=$(curl --silent --show-error --output /dev/null \
        --write-out '%{http_code} %{time_total}' \
        --connect-timeout "$CONNECT_TIMEOUT_SECONDS" \
        --max-time "$MAX_TIME_SECONDS" \
        --header "Host: $FCP_LOAD_HOST" \
        "$FCP_LOAD_TARGET/healthz" 2>&1) || {
        printf '000 -1\n' >"$output"
        return
    }
    printf '%s\n' "$curl_result" >"$output"
}

printf 'starting bounded FCP Fabric liveness load: requests=%s concurrency=%s target=%s ticket=%s\n' \
    "$REQUESTS" "$CONCURRENCY" "$FCP_LOAD_TARGET" "$FCP_LOAD_CHANGE_TICKET"
for ((request = 1; request <= REQUESTS; request += 1)); do
    probe "$request" &
    if (( request % CONCURRENCY == 0 )); then
        wait
    fi
done
wait

readonly finished_epoch=$(date -u +%s)
readonly report="$RESULT_DIR/baseline-${started_epoch}.tsv"
{
    printf 'request\tstatus\tseconds\n'
    for file in "$work_dir"/*; do
        [[ -f "$file" ]] || continue
        read -r status seconds <"$file"
        printf '%s\t%s\t%s\n' "$(basename "$file")" "$status" "$seconds"
    done | sort -n
} >"$report"

readonly total=$(awk 'NR > 1 { count += 1 } END { print count + 0 }' "$report")
readonly successful=$(awk 'NR > 1 && $2 == 204 { count += 1 } END { print count + 0 }' "$report")
readonly failed=$((total - successful))
readonly p50=$(awk 'NR > 1 && $3 >= 0 { print $3 }' "$report" | sort -n | awk '{ values[NR] = $1 } END { if (NR == 0) print "n/a"; else { rank = int((NR + 1) * 0.50); if (rank > NR) rank = NR; print values[rank] } }')
readonly p95=$(awk 'NR > 1 && $3 >= 0 { print $3 }' "$report" | sort -n | awk '{ values[NR] = $1 } END { if (NR == 0) print "n/a"; else { rank = int((NR + 1) * 0.95); if (rank > NR) rank = NR; print values[rank] } }')
readonly p99=$(awk 'NR > 1 && $3 >= 0 { print $3 }' "$report" | sort -n | awk '{ values[NR] = $1 } END { if (NR == 0) print "n/a"; else { rank = int((NR + 1) * 0.99); if (rank > NR) rank = NR; print values[rank] } }')

printf 'completed=%s successful_204=%s failed=%s p50_seconds=%s p95_seconds=%s p99_seconds=%s report=%s\n' \
    "$total" "$successful" "$failed" "$p50" "$p95" "$p99" "$report"

if (( failed > 0 )); then
    exit 1
fi
