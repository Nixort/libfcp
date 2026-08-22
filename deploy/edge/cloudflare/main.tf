# Copyright Nixort <https://github.com/Nixort> 2026.
#
# License: GNU General Public License v3.0 only.
# You can find the license file in the project root.
#
# Federated CFR Connect Protocol (FCP).

terraform {
  required_version = ">= 1.8.0, < 2.0.0"

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.0"
    }
  }
}

variable "cloudflare_zone_id" {
  type      = string
  sensitive = true
}

variable "fabric_public_domain" {
  type = string

  validation {
    condition     = can(regex("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$", var.fabric_public_domain))
    error_message = "fabric_public_domain must be a canonical lowercase DNS name."
  }
}

locals {
  fabric_login_paths = "http.host eq \"${var.fabric_public_domain}\" and http.request.uri.path in {\"/v1/login\" \"/v1/login/totp\" \"/v1/login/session\" \"/v1/login/passkey/begin\" \"/v1/login/passkey/finish\"}"
  fabric_session_paths = "http.host eq \"${var.fabric_public_domain}\" and http.request.uri.path in {\"/v1/session/refresh\" \"/v1/login/enroll/totp/begin\" \"/v1/login/enroll/totp/confirm\"}"
}

# Cloudflare applies this before managed WAF rules. It contains only per-IP
# protection because Fabric identity is established server-side; edge controls
# must never trust an unverified account identifier supplied by a client.
resource "cloudflare_ruleset" "fabric_rate_limit" {
  zone_id = var.cloudflare_zone_id
  name    = "fcp-fabric-rate-limit"
  kind    = "zone"
  phase   = "http_ratelimit"

  rules = [
    {
      ref         = "fabric_login_per_ip"
      action      = "managed_challenge"
      description = "Challenge abusive Fabric login attempts per source IP"
      enabled     = true
      expression  = local.fabric_login_paths
      ratelimit = {
        characteristics      = ["cf.colo.id", "ip.src"]
        period               = 60
        requests_per_period  = 10
        mitigation_timeout   = 600
      }
    },
    {
      ref         = "fabric_session_per_ip"
      action      = "managed_challenge"
      description = "Challenge abusive Fabric session and enrollment mutations per source IP"
      enabled     = true
      expression  = local.fabric_session_paths
      ratelimit = {
        characteristics      = ["cf.colo.id", "ip.src"]
        period               = 60
        requests_per_period  = 30
        mitigation_timeout   = 300
      }
    },
  ]
}

# Explicitly block unexpected public hostnames before the request can reach the
# connector. The application independently validates Host at the loopback
# boundary, so this is defense in depth rather than the sole authorization gate.
resource "cloudflare_ruleset" "fabric_host_allowlist" {
  zone_id = var.cloudflare_zone_id
  name    = "fcp-fabric-host-allowlist"
  kind    = "zone"
  phase   = "http_request_firewall_custom"

  rules = [{
    ref         = "fabric_canonical_host_only"
    action      = "block"
    description = "Block requests that do not target the canonical Fabric hostname"
    enabled     = true
    expression  = "http.host ne \"${var.fabric_public_domain}\""
  }]
}

# Managed WAF rules are plan-dependent. Enable the provider's current managed
# ruleset in the Cloudflare dashboard and review its event feed before switching
# individual rules to Block. It is intentionally not hard-coded here because
# ruleset IDs and plan availability are provider-controlled.
