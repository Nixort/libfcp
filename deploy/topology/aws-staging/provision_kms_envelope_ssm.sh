#!/usr/bin/env bash
# Copyright Nixort <https://github.com/Nixort> 2026.
#
# License: GNU General Public License v3.0 only.
# You can find the license file in the project root.
#
# Federated CFR Connect Protocol (FCP).

set -euo pipefail

: "${AWS_REGION:?set AWS_REGION}"
: "${FCP_STAGING_INSTANCE_ID:?set one staging instance ID from Terraform output}"
: "${FCP_STAGING_CHANGE_TICKET:?set approved non-production change ticket}"
: "${FCP_RDS_MASTER_SECRET_ARN:?set Terraform rds_master_secret_arn output}"
: "${FCP_RDS_ENDPOINT:?set Terraform rds_endpoint output}"
: "${FCP_DATABASE_NAME:?set staging database name}"
: "${FCP_TOTP_KMS_KEY_ARN:?set Terraform totp_kms_key_arn output}"
: "${FCP_STAGING_ACK:?set FCP_FABRIC_STAGING_KMS_PROVISION_APPROVED}"

fail() {
  printf 'FCP Fabric staging KMS provision refused: %s\n' "$1" >&2
  exit 64
}

[[ "$FCP_STAGING_ACK" == FCP_FABRIC_STAGING_KMS_PROVISION_APPROVED ]] \
  || fail 'FCP_STAGING_ACK must equal FCP_FABRIC_STAGING_KMS_PROVISION_APPROVED'
[[ "$FCP_STAGING_CHANGE_TICKET" =~ ^[A-Za-z0-9._-]{3,128}$ ]] \
  || fail 'FCP_STAGING_CHANGE_TICKET must be a bounded identifier'
[[ "$FCP_STAGING_INSTANCE_ID" =~ ^i-[0-9a-f]+$ ]] \
  || fail 'FCP_STAGING_INSTANCE_ID must be an EC2 instance ID'
[[ "$FCP_TOTP_KMS_KEY_ARN" =~ ^arn:aws:kms: ]] \
  || fail 'FCP_TOTP_KMS_KEY_ARN must be an AWS KMS ARN'

readonly remote_script=$(cat <<'REMOTE'
set -euo pipefail
rds_secret=$(aws secretsmanager get-secret-value --secret-id "$FCP_RDS_MASTER_SECRET_ARN" --query SecretString --output text)
rds_username=$(printf '%s' "$rds_secret" | jq -er '.username | strings | select(length > 0)')
rds_password=$(printf '%s' "$rds_secret" | jq -er '.password | strings | select(length > 0)')
export FCP_DATABASE_URL="postgresql://$rds_username:$rds_password@$FCP_RDS_ENDPOINT:5432/$FCP_DATABASE_NAME?sslmode=require"
/usr/local/bin/fcp-fabric migrate
FABRIC_TOTP_KMS_WRAPPING_KEY_REFERENCE="$FCP_TOTP_KMS_KEY_ARN" \
  /usr/local/bin/fcp-fabric-kms provision-totp-data-key
REMOTE
)

command_id=$(aws ssm send-command \
  --region "$AWS_REGION" \
  --instance-ids "$FCP_STAGING_INSTANCE_ID" \
  --document-name AWS-RunShellScript \
  --comment "FCP Fabric staging KMS envelope provision $FCP_STAGING_CHANGE_TICKET" \
  --parameters "commands=$remote_script" \
  --cloud-watch-output-config CloudWatchOutputEnabled=true \
  --query 'Command.CommandId' \
  --output text)

aws ssm wait command-executed \
  --region "$AWS_REGION" \
  --command-id "$command_id" \
  --instance-id "$FCP_STAGING_INSTANCE_ID"

aws ssm get-command-invocation \
  --region "$AWS_REGION" \
  --command-id "$command_id" \
  --instance-id "$FCP_STAGING_INSTANCE_ID" \
  --query '[Status,StandardOutputContent]' \
  --output text

printf '%s\n' 'Copy the returned opaque reference into the secure runtime secret as FABRIC_TOTP_ACTIVE_KEY_REFERENCE; then render secrets and start the Fabric units through a separate approved SSM command.'
