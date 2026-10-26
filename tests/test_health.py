from unittest.mock import patch, MagicMock
from botocore.exceptions import ClientError, ConnectTimeoutError
from app.models import db


def test_health_liveness(client):
    """Verify /health returns 200 ok for liveness probe."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data == {"status": "ok"}


def test_ready_readiness(client):
    """Verify /ready probe checks DB and storage and returns 200 only when both are reachable."""
    mock_s3 = MagicMock()
    mock_s3.head_bucket.return_value = {"ResponseMetadata": {"HTTPStatusCode": 200}}

    with patch("app.health.get_s3_client", return_value=mock_s3):
        response = client.get("/ready")
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "ready"
        assert data["database"] == "connected"
        assert data["storage"] == "connected"
        assert "errors" not in data


def test_ready_dependency_failure_database(client):
    """Verify /ready returns 503 with sanitized status when database fails."""
    mock_s3 = MagicMock()
    mock_s3.head_bucket.return_value = {"ResponseMetadata": {"HTTPStatusCode": 200}}

    with patch.object(db.session, "execute", side_effect=Exception("FATAL: connection to db:5432 failed")), \
         patch("app.health.get_s3_client", return_value=mock_s3):
        response = client.get("/ready")
        assert response.status_code == 503
        data = response.get_json()
        assert data["status"] == "not_ready"
        assert data["database"] == "disconnected"
        assert data["storage"] == "connected"
        assert "errors" in data
        assert "database" in data["errors"]
        assert data["errors"]["database"] == "Database connection failed"
        assert "5432" not in data["errors"]["database"]


def test_ready_dependency_failure_storage(client):
    """Verify /ready returns 503 with sanitized status when storage fails."""
    mock_s3 = MagicMock()
    mock_s3.head_bucket.side_effect = ClientError(
        {"Error": {"Code": "404", "Message": "Bucket does not exist"}},
        "HeadBucket"
    )

    with patch("app.health.get_s3_client", return_value=mock_s3):
        response = client.get("/ready")
        assert response.status_code == 503
        data = response.get_json()
        assert data["status"] == "not_ready"
        assert data["database"] == "connected"
        assert data["storage"] == "disconnected"
        assert "errors" in data
        assert "storage" in data["errors"]
        assert data["errors"]["storage"] == "Storage service unavailable"


def test_ready_both_dependencies_failure(client):
    """Verify /ready returns 503 with both services disconnected when all fail."""
    mock_s3 = MagicMock()
    mock_s3.head_bucket.side_effect = ClientError(
        {"Error": {"Code": "500", "Message": "Internal Server Error"}},
        "HeadBucket"
    )

    with patch.object(db.session, "execute", side_effect=Exception("Database timeout")), \
         patch("app.health.get_s3_client", return_value=mock_s3):
        response = client.get("/ready")
        assert response.status_code == 503
        data = response.get_json()
        assert data["status"] == "not_ready"
        assert data["database"] == "disconnected"
        assert data["storage"] == "disconnected"
        assert data["errors"]["database"] == "Database connection timeout"
        assert data["errors"]["storage"] == "Storage service unavailable"


def test_ready_bounded_timeout_storage_failure(client):
    """Verify /ready handles storage connection timeouts gracefully without blocking."""
    mock_s3 = MagicMock()
    mock_s3.head_bucket.side_effect = ConnectTimeoutError(
        endpoint_url="http://minio:9000"
    )

    with patch("app.health.get_s3_client", return_value=mock_s3):
        response = client.get("/ready")
        assert response.status_code == 503
        data = response.get_json()
        assert data["status"] == "not_ready"
        assert data["storage"] == "disconnected"
        assert data["errors"]["storage"] == "Storage connection timeout"
        assert "http://minio:9000" not in data["errors"]["storage"]


def test_ready_sanitized_errors_leak_no_sensitive_info(client):
    """Verify /ready error payload contains sanitized messages and never leaks passwords, IPs, or URLs."""
    sensitive_db_err = "psycopg2.OperationalError: password authentication failed for user 'postgres' at host '10.0.1.99'"
    sensitive_s3_err = "EndpointConnectionError: Could not connect to http://minio-internal.cluster.local:9000/cloudops-bucket with key AKIAIOSFODNN7EXAMPLE"

    with patch.object(db.session, "execute", side_effect=Exception(sensitive_db_err)), \
         patch("app.health.get_s3_client") as mock_get_s3:
        mock_s3 = MagicMock()
        mock_s3.head_bucket.side_effect = Exception(sensitive_s3_err)
        mock_get_s3.return_value = mock_s3

        response = client.get("/ready")
        assert response.status_code == 503
        data = response.get_json()

        for forbidden in ["10.0.1.99", "postgres", "AKIAIOSFODNN7EXAMPLE", "cluster.local"]:
            assert forbidden not in str(data.get("errors", {}))
