#!/usr/bin/env bash
# Copyright Nixort <https://github.com/Nixort> 2026.
#
# License: GNU General Public License v3.0 only.
# You can find the license file in the project root.
#
# Federated CFR Connect Protocol (FCP).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tf="$root/deploy/postgres/aws-rds/main.tf"
drill="$root/deploy/postgres/scripts/restore_drill_aws.sh"

require() {
  local needle="$1"
  local file="$2"
  grep -Fq -- "$needle" "$file" >/dev/null || {
    printf 'PostgreSQL deployment contract failure: missing %q in %s\n' "$needle" "$file" >&2
    exit 1
  }
}

require 'multi_az       = true' "$tf"
require 'publicly_accessible = false' "$tf"
require 'storage_encrypted     = true' "$tf"
require 'kms_key_id            = var.rds_kms_key_arn' "$tf"
require 'backup_retention_period = 35' "$tf"
require 'deletion_protection     = true' "$tf"
require 'skip_final_snapshot     = false' "$tf"
require 'iam_database_authentication_enabled = true' "$tf"
require 'security_groups = [var.application_security_group_id]' "$tf"
require 'restore-db-instance-to-point-in-time' "$drill"
require 'aws rds wait db-instance-available' "$drill"
require 'refusing restore: FCP_RDS_DRILL_IDENTIFIER must contain drill or restore-test' "$drill"
require 'aws rds delete-db-instance' "$drill"

printf 'PostgreSQL HA/backup deployment contract: PASS\n'
