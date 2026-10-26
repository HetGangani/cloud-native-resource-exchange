import time
import logging
from flask import Blueprint, Response, request, jsonify
from werkzeug.exceptions import HTTPException
from prometheus_client import (
    Counter,
    Histogram,
    REGISTRY,
    generate_latest,
    CONTENT_TYPE_LATEST,
)

logger = logging.getLogger(__name__)

metrics_bp = Blueprint("metrics", __name__)


def _get_or_create_counter(name, documentation, labelnames):
    """Safely retrieve or register a Prometheus Counter to prevent DuplicateTimeseries errors."""
    if name in REGISTRY._names_to_collectors:
        return REGISTRY._names_to_collectors[name]
    return Counter(name, documentation, labelnames)


def _get_or_create_histogram(name, documentation, labelnames, buckets=None):
    """Safely retrieve or register a Prometheus Histogram to prevent DuplicateTimeseries errors."""
    if name in REGISTRY._names_to_collectors:
        return REGISTRY._names_to_collectors[name]
    kwargs = {"buckets": buckets} if buckets else {}
    return Histogram(name, documentation, labelnames, **kwargs)


# Prometheus HTTP Metrics
HTTP_REQUESTS_TOTAL = _get_or_create_counter(
    "http_requests_total",
    "Total count of HTTP requests processed, partitioned by method, endpoint, and status code.",
    ["method", "endpoint", "status_code"],
)

HTTP_REQUEST_DURATION_SECONDS = _get_or_create_histogram(
    "http_request_duration_seconds",
    "Histogram of HTTP request durations in seconds, partitioned by method, endpoint, and status code.",
    ["method", "endpoint", "status_code"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 10.0),
)


@metrics_bp.route("/metrics", methods=["GET"])
def metrics():
    """Prometheus-compatible scrape endpoint."""
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)


def init_observability(app):
    """Attach metrics endpoint, request timers, structured logging, and failure handlers."""
    # Register metrics blueprint
    app.register_blueprint(metrics_bp)

    @app.before_request
    def record_start_time():
        request._start_time = time.perf_counter()

    @app.after_request
    def record_request_metrics(response):
        # Exclude the metrics endpoint itself to prevent artificial metric inflation from scrapers
        if request.path == "/metrics":
            return response

        start_time = getattr(request, "_start_time", None)
        duration = (time.perf_counter() - start_time) if start_time is not None else 0.0

        # Use Flask URL rule template to avoid high cardinality or sensitive dynamic values in labels
        endpoint = request.url_rule.rule if request.url_rule else "unmatched"
        method = request.method
        status_code = str(response.status_code)

        HTTP_REQUESTS_TOTAL.labels(
            method=method,
            endpoint=endpoint,
            status_code=status_code,
        ).inc()

        HTTP_REQUEST_DURATION_SECONDS.labels(
            method=method,
            endpoint=endpoint,
            status_code=status_code,
        ).observe(duration)

        # Structured application logging for request failures (HTTP 4xx / 5xx)
        if response.status_code >= 400:
            logger.warning(
                "REQUEST_FAILURE method=%s endpoint=%s status=%s duration_sec=%.4f",
                method,
                endpoint,
                status_code,
                duration,
            )

        return response

    @app.errorhandler(Exception)
    def handle_unhandled_exception(exc):
        # Allow standard Werkzeug/Flask HTTP exceptions (e.g., 404, 401, 403, 405) to be handled normally
        if isinstance(exc, HTTPException):
            return exc

        endpoint = request.url_rule.rule if request.url_rule else "unmatched"
        logger.error(
            "UNHANDLED_EXCEPTION method=%s endpoint=%s error_type=%s error=\"%s\"",
            request.method,
            endpoint,
            exc.__class__.__name__,
            str(exc),
        )
        return jsonify({
            "status": "error",
            "message": "Internal server error"
        }), 500
