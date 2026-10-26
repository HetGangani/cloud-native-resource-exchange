import logging
from unittest.mock import patch, MagicMock
from botocore.exceptions import ClientError
from app.models import db, User, Resource
from app.metrics import HTTP_REQUESTS_TOTAL


def test_health_liveness_check(client):
    """Verify /health is a lightweight liveness check confirming process is running."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_ready_success_both_dependencies_ready(client):
    """Verify /ready returns 200 ready when both DB and storage dependencies are connected."""
    mock_s3 = MagicMock()
    mock_s3.head_bucket.return_value = {"ResponseMetadata": {"HTTPStatusCode": 200}}

    with patch("app.health.get_s3_client", return_value=mock_s3):
        response = client.get("/ready")
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "ready"
        assert data["database"] == "connected"
        assert data["storage"] == "connected"


def test_ready_db_failure(client):
    """Verify /ready returns 503 not_ready when DB query fails."""
    mock_s3 = MagicMock()
    mock_s3.head_bucket.return_value = {"ResponseMetadata": {"HTTPStatusCode": 200}}

    with patch.object(db.session, "execute", side_effect=Exception("Database connection timeout")), \
         patch("app.health.get_s3_client", return_value=mock_s3):
        response = client.get("/ready")
        assert response.status_code == 503
        data = response.get_json()
        assert data["status"] == "not_ready"
        assert data["database"] == "disconnected"
        assert "Database connection timeout" in data["errors"]["database"]


def test_ready_with_minio_configured_success(client, app):
    """Verify /ready returns 200 and storage connected when MinIO is reachable and bucket exists."""
    mock_s3 = MagicMock()
    mock_s3.head_bucket.return_value = {"ResponseMetadata": {"HTTPStatusCode": 200}}

    with patch("app.health.get_s3_client", return_value=mock_s3):
        app.config["AWS_ENDPOINT_URL"] = "http://minio:9000"
        try:
            response = client.get("/ready")
            assert response.status_code == 200
            data = response.get_json()
            assert data["status"] == "ready"
            assert data["database"] == "connected"
            assert data["storage"] == "connected"
            mock_s3.head_bucket.assert_called_once_with(Bucket="test-sentinel-bucket")
        finally:
            app.config["AWS_ENDPOINT_URL"] = None


def test_ready_with_minio_configured_failure(client, app):
    """Verify /ready returns 503 not_ready when MinIO head_bucket fails."""
    mock_s3 = MagicMock()
    mock_s3.head_bucket.side_effect = ClientError(
        {"Error": {"Code": "404", "Message": "Not Found"}}, "HeadBucket"
    )

    with patch("app.health.get_s3_client", return_value=mock_s3):
        app.config["AWS_ENDPOINT_URL"] = "http://minio:9000"
        try:
            response = client.get("/ready")
            assert response.status_code == 503
            data = response.get_json()
            assert data["status"] == "not_ready"
            assert data["database"] == "connected"
            assert data["storage"] == "disconnected"
            assert "errors" in data
            assert "storage" in data["errors"]
        finally:
            app.config["AWS_ENDPOINT_URL"] = None


def test_metrics_endpoint_returns_prometheus_format(client):
    """Verify /metrics returns 200 and Prometheus text format."""
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "text/plain" in response.content_type
    assert b"http_requests_total" in response.data
    assert b"http_request_duration_seconds" in response.data


def test_metrics_records_request_with_route_template(client, app, regular_user_headers):
    """Verify metrics record method, route template (no raw IDs), and status code."""
    # Create a user and resource in DB for test
    with app.app_context():
        user = User.query.filter_by(username="metric_test_user").first()
        if not user:
            user = User(username="metric_test_user", password_hash="hash123", is_admin=False)
            db.session.add(user)
            db.session.commit()

        res = Resource.query.filter_by(title="Metric Test Resource").first()
        if not res:
            res = Resource(
                title="Metric Test Resource",
                s3_key="resources/test_metric.pdf",
                uploaded_by=user.id,
                approved=True,
            )
            db.session.add(res)
            db.session.commit()
        res_id = res.id

    # Request the resource by specific ID
    resp = client.get(f"/resources/{res_id}", headers=regular_user_headers)
    assert resp.status_code == 200

    # Verify metrics contain the route template '/resources/<int:resource_id>' and NOT '/resources/123'
    metrics_resp = client.get("/metrics")
    metrics_text = metrics_resp.data.decode("utf-8")
    assert 'endpoint="/resources/<int:resource_id>"' in metrics_text
    assert f'endpoint="/resources/{res_id}"' not in metrics_text


def test_metrics_unmatched_route_does_not_leak_raw_url(client):
    """Verify unmatched 404 paths are grouped under endpoint='unmatched' to prevent high cardinality."""
    resp = client.get("/nonexistent/sensitive-token-or-id/12345")
    assert resp.status_code == 404

    metrics_resp = client.get("/metrics")
    metrics_text = metrics_resp.data.decode("utf-8")
    assert 'endpoint="unmatched"' in metrics_text
    assert "sensitive-token-or-id" not in metrics_text


def test_metrics_endpoint_excluded_from_instrumentation(client):
    """Verify scraping /metrics does not increment http_requests_total for /metrics."""
    # Scrape metrics multiple times
    client.get("/metrics")
    client.get("/metrics")

    metrics_resp = client.get("/metrics")
    metrics_text = metrics_resp.data.decode("utf-8")
    # Verify no http_requests_total entry exists with endpoint="/metrics"
    assert 'endpoint="/metrics"' not in metrics_text


def test_structured_logging_on_request_failure(client, caplog):
    """Verify structured log warning on 4xx failure without sensitive tokens/passwords."""
    with caplog.at_level(logging.WARNING):
        response = client.post("/auth/login", json={
            "username": "nonexistent_user",
            "password": "SuperSecretPasswordDoNotLog123"
        })
        assert response.status_code == 401

        # Check for structured REQUEST_FAILURE log
        failure_logs = [r.message for r in caplog.records if "REQUEST_FAILURE" in r.message]
        assert len(failure_logs) >= 1
        log_message = failure_logs[0]
        assert "method=POST" in log_message
        assert 'endpoint=/auth/login' in log_message
        assert "status=401" in log_message

        # Ensure passwords and secret tokens are NEVER logged
        for record in caplog.records:
            assert "SuperSecretPasswordDoNotLog123" not in record.message


def test_unhandled_exception_handling(client, app, caplog):
    """Verify unexpected exceptions return 500 JSON, are logged with UNHANDLED_EXCEPTION, and do not crash."""
    def faulty_handler():
        raise RuntimeError("Unexpected simulated failure in worker")

    with patch.dict(app.view_functions, {"home": faulty_handler}):
        with caplog.at_level(logging.ERROR):
            resp = client.get("/")
            assert resp.status_code == 500
            data = resp.get_json()
            assert data["status"] == "error"
            assert data["message"] == "Internal server error"

            error_logs = [r.message for r in caplog.records if "UNHANDLED_EXCEPTION" in r.message]
            assert len(error_logs) >= 1
            assert "RuntimeError" in error_logs[0]
            assert "method=GET" in error_logs[0]
