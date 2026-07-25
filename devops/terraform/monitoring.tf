# Monitoring — CloudWatch alarms and dashboards

resource "aws_cloudwatch_metric_alarm" "backend_cpu" {
  alarm_name          = "cerberus-backend-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ECS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Backend CPU utilization > 80%"
  alarm_actions       = []

  dimensions = {
    ClusterName = aws_ecs_cluster.cerberus.name
    ServiceName = aws_ecs_service.backend.name
  }
}

resource "aws_cloudwatch_metric_alarm" "db_cpu" {
  alarm_name          = "cerberus-db-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 75
  alarm_description   = "Database CPU utilization > 75%"

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.cerberus.identifier
  }
}

resource "aws_cloudwatch_metric_alarm" "db_storage" {
  alarm_name          = "cerberus-db-storage-low"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "FreeStorageSpace"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 5368709120  # 5GB
  alarm_description   = "Database free storage < 5GB"

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.cerberus.identifier
  }
}

resource "aws_cloudwatch_dashboard" "cerberus" {
  dashboard_name = "Cerberus-AI"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          metrics = [["AWS/ECS", "CPUUtilization", "ClusterName", aws_ecs_cluster.cerberus.name]]
          period  = 300
          stat    = "Average"
          region  = var.aws_region
          title   = "ECS CPU Utilization"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          metrics = [["AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", aws_db_instance.cerberus.identifier]]
          period  = 300
          stat    = "Average"
          region  = var.aws_region
          title   = "RDS CPU Utilization"
        }
      }
    ]
  })
}
