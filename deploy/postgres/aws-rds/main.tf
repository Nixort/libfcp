# Copyright Nixort <https://github.com/Nixort> 2026.
#
# License: GNU General Public License v3.0 only.
# You can find the license file in the project root.
#
# Federated CFR Connect Protocol (FCP).

terraform {
  required_version = ">= 1.8.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "aws_region" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "private_db_subnet_ids" {
  type = list(string)

  validation {
    condition     = length(var.private_db_subnet_ids) >= 2
    error_message = "Multi-AZ RDS requires private subnets in at least two availability zones."
  }
}

variable "application_security_group_id" {
  type = string
}

variable "rds_kms_key_arn" {
  type      = string
  sensitive = true
}

variable "db_identifier" {
  type = string
}

variable "db_name" {
  type    = string
  default = "fcp_fabric"
}

variable "master_username" {
  type      = string
  sensitive = true
}

variable "master_password" {
  type      = string
  sensitive = true
}

variable "final_snapshot_identifier" {
  type = string
}

provider "aws" {
  region = var.aws_region
}

resource "aws_db_subnet_group" "fabric" {
  name       = "${var.db_identifier}-private"
  subnet_ids = var.private_db_subnet_ids

  tags = {
    Name      = "${var.db_identifier}-private"
    Component = "fcp-fabric"
  }
}

resource "aws_security_group" "fabric_postgres" {
  name_prefix = "${var.db_identifier}-postgres-"
  description = "FCP Fabric PostgreSQL accepts only application security-group traffic"
  vpc_id      = var.vpc_id

  ingress {
    description     = "PostgreSQL from Fabric application instances only"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [var.application_security_group_id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Component = "fcp-fabric"
  }
}

resource "aws_db_instance" "fabric" {
  identifier = var.db_identifier

  engine         = "postgres"
  engine_version = "16"
  instance_class = "db.m6g.large"

  allocated_storage     = 100
  max_allocated_storage = 500
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = var.rds_kms_key_arn

  db_name        = var.db_name
  username       = var.master_username
  password       = var.master_password
  port           = 5432
  multi_az       = true
  publicly_accessible = false
  db_subnet_group_name = aws_db_subnet_group.fabric.name
  vpc_security_group_ids = [aws_security_group.fabric.id]

  backup_retention_period = 35
  backup_window           = "03:00-03:30"
  maintenance_window      = "sun:04:00-sun:04:30"
  deletion_protection     = true
  skip_final_snapshot     = false
  final_snapshot_identifier = var.final_snapshot_identifier
  copy_tags_to_snapshot   = true

  auto_minor_version_upgrade = false
  apply_immediately          = false
  iam_database_authentication_enabled = true
  enabled_cloudwatch_logs_exports      = ["postgresql", "upgrade"]

  tags = {
    Component = "fcp-fabric"
    DataClass = "identity-security"
  }
}

output "database_endpoint" {
  value = aws_db_instance.fabric.address
}

output "database_security_group_id" {
  value = aws_security_group.fabric.id
}
