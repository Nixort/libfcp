# Copyright Nixort <https://github.com/Nixort> 2026.
#
# License: GNU General Public License v3.0 only.
# You can find the license file in the project root.
#
# Federated CFR Connect Protocol (FCP).

output "service_instance_ids" {
  value = values(aws_instance.service)[*].id
}

output "service_private_ips" {
  value = values(aws_instance.service)[*].private_ip
}

output "rds_endpoint" {
  value     = aws_db_instance.fabric.address
  sensitive = true
}

output "rds_master_secret_arn" {
  value     = aws_db_instance.fabric.master_user_secret[0].secret_arn
  sensitive = true
}

output "fabric_runtime_secret_arn" {
  value     = aws_secretsmanager_secret.fabric_runtime.arn
  sensitive = true
}

output "cloudflare_tunnel_secret_arn" {
  value     = aws_secretsmanager_secret.cloudflare_tunnel.arn
  sensitive = true
}

output "totp_kms_key_arn" {
  value = aws_kms_key.totp.arn
}

output "rds_kms_key_arn" {
  value = aws_kms_key.rds.arn
}

output "cloudwatch_log_group" {
  value = aws_cloudwatch_log_group.service.name
}
