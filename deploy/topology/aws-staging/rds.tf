# Copyright Nixort <https://github.com/Nixort> 2026.
#
# License: GNU General Public License v3.0 only.
# You can find the license file in the project root.
#
# Federated CFR Connect Protocol (FCP).

resource "aws_security_group" "postgres" {
  name_prefix = "${var.name_prefix}-postgres-"
  description = "FCP Fabric PostgreSQL accepts traffic only from Fabric service hosts"
  vpc_id      = aws_vpc.fabric.id

  ingress {
    description     = "PostgreSQL from Fabric service security group"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.service.id]
  }

  tags = {
    Name = "${var.name_prefix}-postgres"
  }
}

resource "aws_security_group_rule" "service_postgres_egress" {
  type                     = "egress"
  description              = "PostgreSQL to Fabric staging database only"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  security_group_id        = aws_security_group.service.id
  source_security_group_id = aws_security_group.postgres.id
}

resource "aws_db_subnet_group" "fabric" {
  name       = "${var.name_prefix}-postgres"
  subnet_ids = values(aws_subnet.private)[*].id

  tags = {
    Name = "${var.name_prefix}-postgres"
  }
}

resource "aws_db_instance" "fabric" {
  identifier = "${var.name_prefix}-postgres"

  engine         = "postgres"
  engine_version = "16"
  instance_class = var.database_instance_class

  allocated_storage     = 100
  max_allocated_storage = 500
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = aws_kms_key.rds.arn

  db_name                     = var.database_name
  username                    = var.database_master_username
  manage_master_user_password = true
  master_user_secret_kms_key_id = aws_kms_key.secrets.arn
  port                        = 5432
  multi_az                    = true
  publicly_accessible         = false
  db_subnet_group_name        = aws_db_subnet_group.fabric.name
  vpc_security_group_ids      = [aws_security_group.postgres.id]

  backup_retention_period         = 35
  backup_window                   = "03:00-03:30"
  maintenance_window              = "sun:04:00-sun:04:30"
  deletion_protection             = var.rds_deletion_protection
  skip_final_snapshot             = false
  final_snapshot_identifier       = "${var.name_prefix}-postgres-final"
  copy_tags_to_snapshot           = true
  auto_minor_version_upgrade      = false
  apply_immediately               = false
  iam_database_authentication_enabled = true
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  tags = {
    Name = "${var.name_prefix}-postgres"
  }
}
