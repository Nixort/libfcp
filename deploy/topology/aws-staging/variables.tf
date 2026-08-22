# Copyright Nixort <https://github.com/Nixort> 2026.
#
# License: GNU General Public License v3.0 only.
# You can find the license file in the project root.
#
# Federated CFR Connect Protocol (FCP).

variable "aws_region" {
  type = string
}

variable "name_prefix" {
  type    = string
  default = "fcp-fabric-staging"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,40}$", var.name_prefix))
    error_message = "name_prefix must be a lowercase hyphenated identifier between 3 and 41 characters."
  }
}

variable "fabric_public_domain" {
  type = string

  validation {
    condition     = can(regex("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$", var.fabric_public_domain))
    error_message = "fabric_public_domain must be a canonical lowercase DNS hostname."
  }
}

variable "vpc_cidr" {
  type    = string
  default = "10.42.0.0/16"
}

variable "availability_zones" {
  type = list(string)

  validation {
    condition     = length(var.availability_zones) == 2 && length(toset(var.availability_zones)) == 2
    error_message = "availability_zones must contain exactly two distinct zones for the isolated Multi-AZ topology."
  }
}

variable "public_egress_subnet_cidrs" {
  type    = list(string)
  default = ["10.42.0.0/24", "10.42.1.0/24"]

  validation {
    condition     = length(var.public_egress_subnet_cidrs) == 2 && length(toset(var.public_egress_subnet_cidrs)) == 2
    error_message = "public_egress_subnet_cidrs must contain exactly two distinct CIDR ranges."
  }
}

variable "private_subnet_cidrs" {
  type    = list(string)
  default = ["10.42.16.0/20", "10.42.32.0/20"]

  validation {
    condition     = length(var.private_subnet_cidrs) == 2 && length(toset(var.private_subnet_cidrs)) == 2
    error_message = "private_subnet_cidrs must contain exactly two distinct CIDR ranges."
  }
}

variable "service_instance_type" {
  type    = string
  default = "t4g.small"
}

variable "service_ami_id" {
  type = string

  validation {
    condition     = can(regex("^ami-[0-9a-f]+$", var.service_ami_id))
    error_message = "service_ami_id must be an explicit approved AMI ID; the module never selects a mutable latest AMI."
  }
}

variable "service_artifact_s3_uri" {
  type = string

  validation {
    condition     = can(regex("^s3://[^/]+/.+", var.service_artifact_s3_uri))
    error_message = "service_artifact_s3_uri must be a versioned immutable S3 object URI."
  }
}

variable "service_artifact_s3_version_id" {
  type = string

  validation {
    condition     = length(trimspace(var.service_artifact_s3_version_id)) > 0
    error_message = "service_artifact_s3_version_id must pin a specific immutable S3 object version."
  }
}

variable "cloudflared_artifact_s3_uri" {
  type = string

  validation {
    condition     = can(regex("^s3://[^/]+/.+", var.cloudflared_artifact_s3_uri))
    error_message = "cloudflared_artifact_s3_uri must be a versioned immutable S3 object URI."
  }
}

variable "cloudflared_artifact_s3_version_id" {
  type = string

  validation {
    condition     = length(trimspace(var.cloudflared_artifact_s3_version_id)) > 0
    error_message = "cloudflared_artifact_s3_version_id must pin a specific immutable S3 object version."
  }
}

variable "cloudflare_tunnel_id" {
  type = string

  validation {
    condition     = can(regex("^[0-9a-fA-F-]{36}$", var.cloudflare_tunnel_id))
    error_message = "cloudflare_tunnel_id must be a UUID."
  }
}

variable "database_name" {
  type    = string
  default = "fcp_fabric"
}

variable "database_master_username" {
  type    = string
  default = "fabric_master"

  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9_]{0,15}$", var.database_master_username))
    error_message = "database_master_username must meet the bounded PostgreSQL RDS identifier profile."
  }
}

variable "database_instance_class" {
  type    = string
  default = "db.m6g.large"
}

variable "log_retention_days" {
  type    = number
  default = 30

  validation {
    condition     = contains([30, 60, 90, 180, 365, 730, 1827, 3653], var.log_retention_days)
    error_message = "log_retention_days must use an approved CloudWatch retention tier."
  }
}

variable "rds_deletion_protection" {
  type    = bool
  default = true
}

variable "rds_freeable_memory_alarm_bytes" {
  type    = number
  default = 268435456

  validation {
    condition     = var.rds_freeable_memory_alarm_bytes >= 67108864
    error_message = "rds_freeable_memory_alarm_bytes must be at least 64 MiB."
  }
}

variable "rds_connection_alarm_threshold" {
  type    = number
  default = 80

  validation {
    condition     = var.rds_connection_alarm_threshold >= 1 && var.rds_connection_alarm_threshold <= 10000
    error_message = "rds_connection_alarm_threshold must be between 1 and 10000 and tuned after observing the workload baseline."
  }
}

variable "alarm_actions" {
  type    = list(string)
  default = []

  validation {
    condition     = alltrue([for action in var.alarm_actions : length(trimspace(action)) > 0])
    error_message = "alarm_actions must not contain blank action ARNs."
  }
}

variable "tags" {
  type    = map(string)
  default = {}
}

locals {
  common_tags = merge({
    Component   = "fcp-fabric"
    Environment = "staging"
    DataClass   = "identity-security"
    ManagedBy   = "terraform"
  }, var.tags)
}
