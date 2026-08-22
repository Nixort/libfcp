#!/usr/bin/env bash
# Copyright Nixort <https://github.com/Nixort> 2026.
#
# License: GNU General Public License v3.0 only.
# You can find the license file in the project root.
#
# Federated CFR Connect Protocol (FCP).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
config="$root/deploy/edge/cloudflare/config.yml.template"
policy="$root/deploy/edge/cloudflare/main.tf"
fabric_unit="$root/deploy/systemd/fcp-fabric.service"
tunnel_unit="$root/deploy/systemd/fcp-fabric-cloudflared.service"

require() {
  local needle="$1"
  local file="$2"
  grep -Fqx -- "$needle" "$file" >/dev/null || {
    printf 'edge contract failure: missing exact line %q in %s\n' "$needle" "$file" >&2
    exit 1
  }
}

require '    service: http://127.0.0.1:8080' "$config"
require '  - service: http_status:404' "$config"
require 'Environment=FABRIC_BIND=127.0.0.1:8080' "$fabric_unit"
require 'NoNewPrivileges=yes' "$fabric_unit"
require 'ProtectSystem=strict' "$fabric_unit"
require 'Requires=fcp-fabric.service' "$tunnel_unit"
require 'NoNewPrivileges=yes' "$tunnel_unit"
grep -Eq 'phase[[:space:]]*=[[:space:]]*"http_ratelimit"' "$policy"
grep -Eq 'phase[[:space:]]*=[[:space:]]*"http_request_firewall_custom"' "$policy"
grep -Eq 'action[[:space:]]*=[[:space:]]*"managed_challenge"' "$policy"
grep -Eq 'characteristics[[:space:]]*=[[:space:]]*\["cf.colo.id", "ip.src"\]' "$policy"
grep -Eq 'expression[[:space:]]*=[[:space:]]*"http.host ne \\"\$\{var.fabric_public_domain\}\\""' "$policy"

printf 'edge deployment contract: PASS\n'
