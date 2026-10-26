import importlib
import json
from unittest.mock import MagicMock, patch

auto_block = importlib.import_module("lambda.auto_block_suspicious")
lambda_handler = auto_block.lambda_handler


@patch("lambda.auto_block_suspicious.logs_client")
def test_lambda_handler_sns_event(mock_logs):
    """Verify Lambda handler parses SNS alarm event and queries CloudWatch Logs."""
    mock_logs.start_query.return_value = {"queryId": "query-12345"}

    event = {
        "Records": [
            {
                "EventSource": "aws:sns",
                "Sns": {
                    "Subject": "ALARM: RepeatedLoginFailures",
                    "Message": json.dumps({
                        "AlarmName": "cloudops-sentinel-suspicious-login-alarm",
                        "NewStateValue": "ALARM",
                        "NewStateReason": "Threshold Crossed",
                    }),
                },
            }
        ]
    }
    context = MagicMock()

    response = lambda_handler(event, context)
    assert response["statusCode"] == 200
    body = json.loads(response["body"])
    assert body["status"] == "mitigated"
    mock_logs.start_query.assert_called_once()


@patch("lambda.auto_block_suspicious.logs_client")
def test_lambda_handler_direct_alarm_event(mock_logs):
    """Verify Lambda handler handles direct CloudWatch Alarm event."""
    mock_logs.start_query.return_value = {"queryId": "query-67890"}

    event = {
        "detail": {
            "alarmName": "cloudops-sentinel-suspicious-login-alarm",
            "state": {"value": "ALARM"},
        }
    }
    context = MagicMock()

    response = lambda_handler(event, context)
    assert response["statusCode"] == 200
    mock_logs.start_query.assert_called_once()
