#!/usr/bin/env bash
# Copyright Nixort <https://github.com/Nixort> 2026.
#
# License: GNU General Public License v3.0 only.
# You can find the license file in the project root.
#
# Federated CFR Connect Protocol (FCP).

set -euo pipefail

readonly ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
readonly PROMETHEUS="$ROOT/deploy/observability/prometheus/prometheus.yml.template"
readonly BLACKBOX="$ROOT/deploy/observability/prometheus/blackbox.yml.template"
readonly ALERTS="$ROOT/deploy/observability/prometheus/fcp-fabric-alerts.yml"
readonly OBSERVABILITY_README="$ROOT/deploy/observability/README.md"
readonly AUDIT_RETENTION="$ROOT/deploy/operations/audit-retention.md"
readonly SECRETS_README="$ROOT/deploy/secrets/README.md"
readonly SECRET_VALIDATOR="$ROOT/deploy/secrets/scripts/validate_fcp_fabric_env.sh"
readonly SERVICE_MAIN="$ROOT/crates/fcp-fabric-service/src/main.rs"
readonly KMS_CLI="$ROOT/crates/fcp-fabric-service/src/bin/fcp-fabric-kms.rs"

fail() {
    printf 'production operations contract failed: %s\n' "$1" >&2
    exit 1
}

require() {
    local pattern=$1
    local file=$2
    grep -Fq -- "$pattern" "$file" || fail "missing $pattern in ${file#$ROOT/}"
}

for file in "$PROMETHEUS" "$BLACKBOX" "$ALERTS" "$OBSERVABILITY_README" \
    "$AUDIT_RETENTION" "$SECRETS_README" "$SECRET_VALIDATOR" "$SERVICE_MAIN" "$KMS_CLI"; do
    [[ -f "$file" ]] || fail "missing required asset ${file#$ROOT/}"
done

require '127.0.0.1:8080/healthz' "$PROMETHEUS"
require '127.0.0.1:8080/readyz' "$PROMETHEUS"
require 'replacement: 127.0.0.1:9115' "$PROMETHEUS"
require 'Host: ["<FABRIC_PUBLIC_DOMAIN>"]' "$BLACKBOX"
require 'valid_status_codes: [204]' "$BLACKBOX"
require 'valid_status_codes: [200]' "$BLACKBOX"
require 'FcpFabricLivenessFailed' "$ALERTS"
require 'FcpFabricReadinessFailed' "$ALERTS"
require 'FcpFabricProbeTargetMissing' "$ALERTS"
require 'audit_events' "$AUDIT_RETENTION"
require 'does **not** implement an automatic `DELETE` job' "$AUDIT_RETENTION"
require 'object lock' "$AUDIT_RETENTION"
require '--bin fcp-fabric-kms -- provision-totp-data-key' "$SECRETS_README"
require 'not zero-downtime key rotation' "$SECRETS_README"
require 'run this validator as root' "$SECRET_VALIDATOR"
require 'FABRIC_TOTP_ACTIVE_KEY_REFERENCE' "$SECRET_VALIDATOR"
require 'FABRIC_SESSION_DIGEST_KEY' "$SECRET_VALIDATOR"
require 'router_with_mfa_session' "$SERVICE_MAIN"
require 'AwsKmsTotpKeyProvider::from_default_environment' "$SERVICE_MAIN"
require 'AwsKmsFeatureRequired' "$SERVICE_MAIN"
require 'FCP_DATABASE_URL' "$KMS_CLI"
require 'FABRIC_TOTP_KMS_WRAPPING_KEY_REFERENCE' "$KMS_CLI"
require 'provision-totp-data-key' "$KMS_CLI"

if grep -Fq -- '.arg(' "$KMS_CLI" || grep -Fq -- '--database' "$KMS_CLI"; then
    fail 'KMS provisioning CLI must not accept database or secret arguments'
fi

bash -n "$SECRET_VALIDATOR"
bash -n "$0"
printf 'production operations contract passed.\n'
