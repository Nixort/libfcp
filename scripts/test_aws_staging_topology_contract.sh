#!/usr/bin/env bash
# Copyright Nixort <https://github.com/Nixort> 2026.
#
# License: GNU General Public License v3.0 only.
# You can find the license file in the project root.
#
# Federated CFR Connect Protocol (FCP).

set -euo pipefail

readonly ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
readonly TOPOLOGY="$ROOT/deploy/topology/aws-staging"

fail() {
  printf 'AWS staging topology contract failed: %s\n' "$1" >&2
  exit 1
}

require() {
  local pattern=$1
  local file=$2
  grep -Fq -- "$pattern" "$file" || fail "missing $pattern in ${file#$ROOT/}"
}

for file in \
  "$TOPOLOGY/versions.tf" \
  "$TOPOLOGY/variables.tf" \
  "$TOPOLOGY/network.tf" \
  "$TOPOLOGY/kms.tf" \
  "$TOPOLOGY/secrets.tf" \
  "$TOPOLOGY/iam.tf" \
  "$TOPOLOGY/rds.tf" \
  "$TOPOLOGY/compute.tf" \
  "$TOPOLOGY/observability.tf" \
  "$TOPOLOGY/outputs.tf" \
  "$TOPOLOGY/README.md" \
  "$TOPOLOGY/templates/bootstrap.sh.tftpl" \
  "$TOPOLOGY/provision_kms_envelope_ssm.sh" \
  "$TOPOLOGY/activate_services_ssm.sh"; do
  [[ -f "$file" ]] || fail "missing required asset ${file#$ROOT/}"
done

require 'multi_az                    = true' "$TOPOLOGY/rds.tf"
require 'storage_encrypted     = true' "$TOPOLOGY/rds.tf"
require 'manage_master_user_password = true' "$TOPOLOGY/rds.tf"
require 'backup_retention_period         = 35' "$TOPOLOGY/rds.tf"
require 'publicly_accessible         = false' "$TOPOLOGY/rds.tf"
require 'service_postgres_egress' "$TOPOLOGY/rds.tf"
require 'source_security_group_id = aws_security_group.postgres.id' "$TOPOLOGY/rds.tf"
require 'deletion_protection             = var.rds_deletion_protection' "$TOPOLOGY/rds.tf"
require 'aws_kms_key" "totp' "$TOPOLOGY/kms.tf"
require 'enable_key_rotation     = true' "$TOPOLOGY/kms.tf"
require 'AmazonSSMManagedInstanceCore' "$TOPOLOGY/iam.tf"
require 'kms:EncryptionContext:fcp-fabric-purpose' "$TOPOLOGY/iam.tf"
require 'http_tokens                 = "required"' "$TOPOLOGY/compute.tf"
require 'associate_public_ip_address = false' "$TOPOLOGY/compute.tf"
require 'fcp-fabric.service' "$TOPOLOGY/compute.tf"
require 'aws_nat_gateway" "fabric' "$TOPOLOGY/network.tf"
require 'Cloudflare Tunnel TCP connectivity' "$TOPOLOGY/network.tf"
require 'Cloudflare Tunnel QUIC connectivity' "$TOPOLOGY/network.tf"
require '"ssmmessages"' "$TOPOLOGY/network.tf"
require '"secretsmanager"' "$TOPOLOGY/network.tf"
require 'FCP_DATABASE_URL' "$TOPOLOGY/templates/bootstrap.sh.tftpl"
require 'FABRIC_BIND=127.0.0.1:8080' "$ROOT/deploy/systemd/fcp-fabric.service"
require 'FCP_FABRIC_STAGING_KMS_PROVISION_APPROVED' "$TOPOLOGY/provision_kms_envelope_ssm.sh"
require 'FCP_FABRIC_STAGING_SERVICE_ACTIVATION_APPROVED' "$TOPOLOGY/activate_services_ssm.sh"
require 'does not create secret values' "$TOPOLOGY/README.md"
require 'aws_cloudwatch_metric_alarm" "rds_cpu"' "$TOPOLOGY/observability.tf"
require 'aws_cloudwatch_metric_alarm" "rds_free_storage"' "$TOPOLOGY/observability.tf"
require 'aws_cloudwatch_metric_alarm" "rds_freeable_memory"' "$TOPOLOGY/observability.tf"
require 'aws_cloudwatch_metric_alarm" "rds_connections"' "$TOPOLOGY/observability.tf"
require 'alarm_actions        = var.alarm_actions' "$TOPOLOGY/observability.tf"
require 'variable "rds_freeable_memory_alarm_bytes"' "$TOPOLOGY/variables.tf"
require 'variable "rds_connection_alarm_threshold"' "$TOPOLOGY/variables.tf"
require 'variable "alarm_actions"' "$TOPOLOGY/variables.tf"

if grep -Eiq 'master_password|aws_access_key|aws_secret_access_key|cloudflare_api_token' "$TOPOLOGY"/*.tf "$TOPOLOGY"/templates/*.tftpl "$TOPOLOGY"/*.tfvars.example; then
  fail 'topology source contains a prohibited plaintext credential variable or value'
fi

bash -n "$TOPOLOGY/provision_kms_envelope_ssm.sh"
bash -n "$TOPOLOGY/activate_services_ssm.sh"
bash -n <(sed -E 's/\$\{[^}]+\}/placeholder/g' "$TOPOLOGY/templates/bootstrap.sh.tftpl")

printf 'AWS staging topology contract passed.\n'
