import logging
from flask import Blueprint, jsonify, current_app
from sqlalchemy import text
from app.models import db
from app.storage import get_s3_client, READINESS_BOTO_CONFIG

health_bp = Blueprint("health", __name__)
logger = logging.getLogger(__name__)

READINESS_DB_TIMEOUT = 3.0  # Bounded database query timeout in seconds


@health_bp.route("/health", methods=["GET"])
def health():
    """Liveness probe: verifies the application process is running."""
    return jsonify({"status": "ok"}), 200


@health_bp.route("/ready", methods=["GET"])
def ready():
    """Readiness probe: verifies dependencies required for normal application operation."""
    services = {}
    errors = {}
    is_ready = True

    # 1. Database readiness check with bounded execution timeout
    try:
        db.session.execute(
            text("SELECT 1"),
            execution_options={"timeout": READINESS_DB_TIMEOUT}
        )
        services["database"] = "connected"
    except Exception as e:
        is_ready = False
        services["database"] = "disconnected"
        err_msg = str(e).lower()
        if "timeout" in err_msg or "timed out" in err_msg:
            errors["database"] = "Database connection timeout"
        else:
            errors["database"] = "Database connection failed"
        logger.error("Readiness check failed for database: %s", e)

    # 2. MinIO / S3 Object Storage readiness check with bounded connect/read timeouts and no retries
    bucket_name = current_app.config.get("S3_BUCKET_NAME", "cloudops-sentinel-resources")
    try:
        s3_client = get_s3_client(config=READINESS_BOTO_CONFIG)
        s3_client.head_bucket(Bucket=bucket_name)
        services["storage"] = "connected"
    except Exception as e:
        is_ready = False
        services["storage"] = "disconnected"
        err_msg = str(e).lower()
        if "timeout" in err_msg or "timed out" in err_msg:
            errors["storage"] = "Storage connection timeout"
        else:
            errors["storage"] = "Storage service unavailable"
        logger.error("Readiness check failed for storage: %s", e)

    # Both PostgreSQL and MinIO/S3 are required dependencies for readiness
    if services.get("database") != "connected" or services.get("storage") != "connected":
        is_ready = False

    status_code = 200 if is_ready else 503
    response_payload = {
        "status": "ready" if is_ready else "not_ready",
        **services
    }
    if not is_ready and errors:
        response_payload["errors"] = errors

    return jsonify(response_payload), status_code
