# Copyright Nixort <https://github.com/Nixort> 2026.
#
# License: GNU General Public License v3.0 only.
# You can find the license file in the project root.
#
# Federated CFR Connect Protocol (FCP).

resource "aws_secretsmanager_secret" "fabric_runtime" {
  name                    = "${var.name_prefix}/runtime"
  description             = "FCP Fabric staging environment values; secret value is injected outside Terraform state"
  kms_key_id              = aws_kms_key.secrets.arn
  recovery_window_in_days = 30

  tags = {
    Name = "${var.name_prefix}-runtime"
  }
}

resource "aws_secretsmanager_secret" "cloudflare_tunnel" {
  name                    = "${var.name_prefix}/cloudflare-tunnel"
  description             = "FCP Fabric staging Cloudflare Tunnel credential JSON; secret value is injected outside Terraform state"
  kms_key_id              = aws_kms_key.secrets.arn
  recovery_window_in_days = 30

  tags = {
    Name = "${var.name_prefix}-cloudflare-tunnel"
  }
}
