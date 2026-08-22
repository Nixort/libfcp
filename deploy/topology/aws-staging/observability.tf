# Copyright Nixort <https://github.com/Nixort> 2026.
#
# License: GNU General Public License v3.0 only.
# You can find the license file in the project root.
#
# Federated CFR Connect Protocol (FCP).

resource "aws_cloudwatch_log_group" "service" {
  name              = "/fcp-fabric/${var.name_prefix}/service"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.secrets.arn
}

resource "aws_cloudwatch_metric_alarm" "rds_cpu" {
  alarm_name          = "${var.name_prefix}-rds-cpu"
  alarm_description   = "FCP Fabric staging RDS CPU remains above 80 percent for fifteen minutes."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 300
  statistic            = "Average"
  threshold           = 80
  treat_missing_data   = "breaching"
  alarm_actions        = var.alarm_actions

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.fabric.id
  }
}

resource "aws_cloudwatch_metric_alarm" "rds_free_storage" {
  alarm_name          = "${var.name_prefix}-rds-free-storage"
  alarm_description   = "FCP Fabric staging RDS has less than 15 percent of initial allocated storage free."
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 3
  metric_name         = "FreeStorageSpace"
  namespace           = "AWS/RDS"
  period              = 300
  statistic            = "Average"
  threshold           = 16106127360
  treat_missing_data   = "breaching"
  alarm_actions        = var.alarm_actions

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.fabric.id
  }
}

resource "aws_cloudwatch_metric_alarm" "rds_freeable_memory" {
  alarm_name          = "${var.name_prefix}-rds-freeable-memory"
  alarm_description   = "FCP Fabric staging RDS freeable memory remains below the configured safety floor."
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 3
  metric_name         = "FreeableMemory"
  namespace           = "AWS/RDS"
  period              = 300
  statistic            = "Average"
  threshold           = var.rds_freeable_memory_alarm_bytes
  treat_missing_data   = "breaching"
  alarm_actions        = var.alarm_actions

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.fabric.id
  }
}

resource "aws_cloudwatch_metric_alarm" "rds_connections" {
  alarm_name          = "${var.name_prefix}-rds-connections"
  alarm_description   = "FCP Fabric staging RDS connections remain above the configured workload baseline threshold."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "DatabaseConnections"
  namespace           = "AWS/RDS"
  period              = 300
  statistic            = "Average"
  threshold           = var.rds_connection_alarm_threshold
  treat_missing_data   = "breaching"
  alarm_actions        = var.alarm_actions

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.fabric.id
  }
}
