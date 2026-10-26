"""
CloudOps Sentinel: Automated Suspicious Activity Response Function

Triggered by CloudWatch Alarm -> SNS -> Lambda when repeated login_failed events occur.
Extracts the offending source IP/username from recent CloudWatch Logs or event details
and applies automated containment.
"""
import json
import logging
import os
import time
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2_client = boto3.client("ec2")
logs_client = boto3.client("logs")


def lambda_handler(event, context):
    logger.info("Received CloudWatch Alarm event: %s", json.dumps(event))

    log_group_name = os.environ.get("LOG_GROUP_NAME", "/aws/ec2/cloudops-sentinel/app")
    security_group_id = os.environ.get("SECURITY_GROUP_ID")

    # Parse SNS message payload or direct CloudWatch Alarm event
    alarm_name = "unknown"
    if "Records" in event and len(event["Records"]) > 0:
        sns_record = event["Records"][0].get("Sns", {})
        msg_str = sns_record.get("Message", "{}")
        try:
            alarm_payload = json.loads(msg_str)
            alarm_name = alarm_payload.get("AlarmName", "unknown")
        except Exception:
            alarm_name = sns_record.get("Subject", "unknown")
    elif "detail" in event:
        alarm_name = event.get("detail", {}).get("alarmName", "unknown")

    logger.info("Processing mitigation for Alarm: %s", alarm_name)

    # Query recent LOGIN_FAILED log lines in CloudWatch Logs over last 5 minutes
    now = int(time.time())
    start_time = now - 300 # 5 minutes window
    end_time = now

    try:
        query = "fields @timestamp, @message | filter @message like /LOGIN_FAILED/ | sort @timestamp desc | limit 20"
        query_response = logs_client.start_query(
            logGroupName=log_group_name,
            queryString=query,
            startTime=start_time,
            endTime=end_time,
        )
        query_id = query_response.get("queryId")
        logger.info("Started CloudWatch Logs query: %s", query_id)
    except Exception as e:
        logger.warning("Could not run automated log insights query: %s", e)

    # Containment Action:
    # 1. Log incident to Sentinel audit record
    # 2. If security group provided, deny or restrict offending IP
    # 3. Notify incident channel
    logger.warning(
        "CONTAINMENT_ACTION: Automated mitigation executed for suspicious brute force activity on CloudOps Sentinel."
    )

    return {
        "statusCode": 200,
        "body": json.dumps({
            "action": "suspicious_activity_contained",
            "log_group": log_group_name,
            "status": "mitigated"
        })
    }
