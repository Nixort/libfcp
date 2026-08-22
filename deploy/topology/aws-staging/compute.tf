# Copyright Nixort <https://github.com/Nixort> 2026.
#
# License: GNU General Public License v3.0 only.
# You can find the license file in the project root.
#
# Federated CFR Connect Protocol (FCP).

locals {
  fcp_service_unit_base64 = base64encode(file("${path.module}/../../systemd/fcp-fabric.service"))
  cloudflared_service_unit_base64 = base64encode(file("${path.module}/../../systemd/fcp-fabric-cloudflared.service"))
}

resource "aws_instance" "service" {
  for_each = aws_subnet.private

  ami                         = var.service_ami_id
  instance_type               = var.service_instance_type
  subnet_id                   = each.value.id
  associate_public_ip_address = false
  iam_instance_profile        = aws_iam_instance_profile.service.name
  vpc_security_group_ids      = [aws_security_group.service.id]
  monitoring                  = true

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    encrypted   = true
    kms_key_id  = aws_kms_key.secrets.arn
    volume_type = "gp3"
    volume_size = 20
  }

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/templates/bootstrap.sh.tftpl", {
    service_artifact_s3_uri                 = var.service_artifact_s3_uri
    service_artifact_s3_version_id          = var.service_artifact_s3_version_id
    cloudflared_artifact_s3_uri             = var.cloudflared_artifact_s3_uri
    cloudflared_artifact_s3_version_id      = var.cloudflared_artifact_s3_version_id
    fabric_public_domain                    = var.fabric_public_domain
    cloudflare_tunnel_id                    = var.cloudflare_tunnel_id
    rds_master_secret_arn                   = aws_db_instance.fabric.master_user_secret[0].secret_arn
    fabric_runtime_secret_arn               = aws_secretsmanager_secret.fabric_runtime.arn
    cloudflare_tunnel_credentials_secret_arn = aws_secretsmanager_secret.cloudflare_tunnel.arn
    rds_endpoint                            = aws_db_instance.fabric.address
    database_name                           = var.database_name
    cloudwatch_log_group                    = aws_cloudwatch_log_group.service.name
    log_retention_days                      = var.log_retention_days
    fcp_service_unit_base64                 = local.fcp_service_unit_base64
    cloudflared_service_unit_base64         = local.cloudflared_service_unit_base64
  })

  depends_on = [
    aws_vpc_endpoint.s3,
    aws_vpc_endpoint.interface,
    aws_db_instance.fabric,
  ]

  tags = {
    Name = "${var.name_prefix}-service-${each.key}"
  }
}
