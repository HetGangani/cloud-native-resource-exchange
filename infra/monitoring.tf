# CloudWatch Log Group for Application Logs
resource "aws_cloudwatch_log_group" "app_logs" {
  name              = "/aws/ec2/${var.project_name}/app"
  retention_in_days = 30

  tags = {
    Name = "${var.project_name}-app-logs"
  }
}

# SNS Topic for CloudOps Sentinel Alerts
resource "aws_sns_topic" "alerts" {
  name = "${var.project_name}-alerts"
}

# 1. Suspicious Activity Metric Filter: Counts repeated LOGIN_FAILED events
resource "aws_cloudwatch_log_metric_filter" "login_failed_filter" {
  name           = "RepeatedLoginFailures"
  pattern        = "[timestamp, level, logger, msg = \"*LOGIN_FAILED*\"]"
  log_group_name = aws_cloudwatch_log_group.app_logs.name

  metric_transformation {
    name          = "LoginFailedCount"
    namespace     = "CloudOpsSentinel/Security"
    value         = "1"
    default_value = "0"
  }
}

# Suspicious Activity Alarm: Triggers if >= 5 failed logins within 5 minutes
resource "aws_cloudwatch_metric_alarm" "suspicious_login_alarm" {
  alarm_name          = "${var.project_name}-suspicious-login-alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "LoginFailedCount"
  namespace           = "CloudOpsSentinel/Security"
  period              = 300 # 5 minutes
  statistic           = "Sum"
  threshold           = 5
  alarm_description   = "Triggered when repeated failed login attempts indicate brute force attack"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  tags = {
    Type = "Security"
  }
}

# 2. Host CPU Utilization Alarm (> 80% for 2 consecutive 5-minute periods)
resource "aws_cloudwatch_metric_alarm" "ec2_cpu_high" {
  alarm_name          = "${var.project_name}-ec2-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Triggers when EC2 web host CPU exceeds 80%"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    InstanceId = aws_instance.web.id
  }
}

# 3. RDS Free Storage Space Alarm (< 4 GB remaining on 20 GB allocation)
resource "aws_cloudwatch_metric_alarm" "rds_low_storage" {
  alarm_name          = "${var.project_name}-rds-low-storage"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "FreeStorageSpace"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 4294967296 # 4 GB in bytes (< 20% free)
  alarm_description   = "Triggers when RDS free storage drops below 20%"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.postgres.identifier
  }
}
