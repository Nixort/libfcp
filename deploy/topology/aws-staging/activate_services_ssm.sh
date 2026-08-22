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
: "${FCP_STAGING_DOMAIN:?set canonical staging hostname}"
: "${FCP_STAGING_CHANGE_TICKET:?set approved non-production change ticket}"
: "${FCP_STAGING_ACK:?set FCP_FABRIC_STAGING_SERVICE_ACTIVATION_APPROVED}"

fail() {
  printf 'FCP Fabric staging service activation refused: %s\n' "$1" >&2
  exit 64
}

[[ "$FCP_STAGING_ACK" == FCP_FABRIC_STAGING_SERVICE_ACTIVATION_APPROVED ]] \
  || fail 'FCP_STAGING_ACK must equal FCP_FABRIC_STAGING_SERVICE_ACTIVATION_APPROVED'
[[ "$FCP_STAGING_CHANGE_TICKET" =~ ^[A-Za-z0-9._-]{3,128}$ ]] \
  || fail 'FCP_STAGING_CHANGE_TICKET must be a bounded identifier'
[[ "$FCP_STAGING_INSTANCE_ID" =~ ^i-[0-9a-f]+$ ]] \
  || fail 'FCP_STAGING_INSTANCE_ID must be an EC2 instance ID'
[[ "$FCP_STAGING_DOMAIN" =~ ^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$ ]] \
  || fail 'FCP_STAGING_DOMAIN must be a canonical lowercase hostname'

readonly remote_script=$(cat <<'REMOTE'
set -euo pipefail
/usr/local/libexec/fcp-fabric-sync-secrets
systemctl enable --now fcp-fabric.service fcp-fabric-cloudflared.service
systemctl is-active --quiet fcp-fabric.service
systemctl is-active --quiet fcp-fabric-cloudflared.service
curl --silent --show-error --fail --output /dev/null \
  --header "Host: $FCP_STAGING_DOMAIN" \
  http://127.0.0.1:8080/healthz
REMOTE
)

command_id=$(aws ssm send-command \
  --region "$AWS_REGION" \
  --instance-ids "$FCP_STAGING_INSTANCE_ID" \
  --document-name AWS-RunShellScript \
  --comment "FCP Fabric staging service activation $FCP_STAGING_CHANGE_TICKET" \
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
  --query '[Status,StandardErrorContent]' \
  --output text
