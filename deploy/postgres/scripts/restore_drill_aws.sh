#!/usr/bin/env bash
# Copyright Nixort <https://github.com/Nixort> 2026.
#
# License: GNU General Public License v3.0 only.
# You can find the license file in the project root.
#
# Federated CFR Connect Protocol (FCP).
set -euo pipefail

: "${AWS_REGION:?set AWS_REGION}"
: "${FCP_RDS_SOURCE_IDENTIFIER:?set FCP_RDS_SOURCE_IDENTIFIER}"
: "${FCP_RDS_DRILL_IDENTIFIER:?set an unused disposable drill identifier}"
: "${FCP_RDS_RESTORE_TIME_UTC:?set ISO-8601 UTC restore point time}"
: "${FCP_RDS_DRILL_SECURITY_GROUP_ID:?set drill application security group ID}"
: "${FCP_RDS_DRILL_SUBNET_GROUP:?set private DB subnet group name}"
: "${FCP_RDS_DRILL_PARAMETER_GROUP:?set PostgreSQL parameter group name}"

case "$FCP_RDS_DRILL_IDENTIFIER" in
  *drill*|*restore-test*) ;;
  *)
    printf '%s\n' 'refusing restore: FCP_RDS_DRILL_IDENTIFIER must contain drill or restore-test' >&2
    exit 64
    ;;
esac

aws rds describe-db-instances \
  --region "$AWS_REGION" \
  --db-instance-identifier "$FCP_RDS_DRILL_IDENTIFIER" >/dev/null 2>&1 && {
  printf '%s\n' 'refusing restore: drill identifier already exists' >&2
  exit 65
}

aws rds restore-db-instance-to-point-in-time \
  --region "$AWS_REGION" \
  --source-db-instance-identifier "$FCP_RDS_SOURCE_IDENTIFIER" \
  --target-db-instance-identifier "$FCP_RDS_DRILL_IDENTIFIER" \
  --restore-time "$FCP_RDS_RESTORE_TIME_UTC" \
  --db-instance-class db.m6g.large \
  --db-subnet-group-name "$FCP_RDS_DRILL_SUBNET_GROUP" \
  --vpc-security-group-ids "$FCP_RDS_DRILL_SECURITY_GROUP_ID" \
  --db-parameter-group-name "$FCP_RDS_DRILL_PARAMETER_GROUP" \
  --no-publicly-accessible \
  --copy-tags-to-snapshot \
  --tags Key=Component,Value=fcp-fabric-restore-drill Key=DataClass,Value=identity-security

aws rds wait db-instance-available \
  --region "$AWS_REGION" \
  --db-instance-identifier "$FCP_RDS_DRILL_IDENTIFIER"

endpoint="$(aws rds describe-db-instances \
  --region "$AWS_REGION" \
  --db-instance-identifier "$FCP_RDS_DRILL_IDENTIFIER" \
  --query 'DBInstances[0].Endpoint.Address' \
  --output text)"
printf 'restore drill instance is available at %s\n' "$endpoint"
printf '%s\n' 'Run read-only migration/version and application integrity checks against this endpoint before deletion.'
printf '%s\n' 'Delete only after documented approval: aws rds delete-db-instance --skip-final-snapshot --db-instance-identifier <drill-id>.'
