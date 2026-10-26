import logging
import uuid
import os
from flask import current_app
import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError
from werkzeug.utils import secure_filename

logger = logging.getLogger(__name__)

# Bounded timeouts and disabled SDK retries for readiness checks
READINESS_BOTO_CONFIG = BotoConfig(
    connect_timeout=2.0,
    read_timeout=3.0,
    retries={"max_attempts": 1, "mode": "standard"},
)

_client_cache = {}


def get_s3_client(endpoint_url=None, config=None):
    """Build and return a boto3 S3 client configured with app settings."""
    region = current_app.config.get("AWS_REGION", "us-east-1")
    endpoint = endpoint_url or current_app.config.get("AWS_ENDPOINT_URL")

    # Cache key includes region, endpoint, and config signature
    config_key = (
        getattr(config, "connect_timeout", None),
        getattr(config, "read_timeout", None),
        str(getattr(config, "retries", None)),
    ) if config else None

    cache_key = (region, endpoint, config_key)
    if cache_key in _client_cache:
        return _client_cache[cache_key]

    kwargs = {"region_name": region}
    if endpoint:
        kwargs["endpoint_url"] = endpoint
    if config:
        kwargs["config"] = config

    client = boto3.client("s3", **kwargs)
    _client_cache[cache_key] = client
    return client


def get_s3_readiness_client(endpoint_url=None):
    """Build and return an S3 client with aggressive bounded timeouts for readiness checks."""
    return get_s3_client(endpoint_url=endpoint_url, config=READINESS_BOTO_CONFIG)


def upload_file_to_s3(file_obj, original_filename, content_type=None):
    """Uploads a file object directly to S3 using upload_fileobj.
    
    Streams file directly to S3 without persisting to local disk.
    Returns the generated s3_key.
    """
    bucket_name = current_app.config.get("S3_BUCKET_NAME")
    cleaned_filename = secure_filename(original_filename) or "unnamed_file"
    unique_prefix = uuid.uuid4().hex[:12]
    s3_key = f"resources/{unique_prefix}_{cleaned_filename}"

    extra_args = {}
    if content_type:
        extra_args["ContentType"] = content_type

    s3_client = get_s3_client()
    try:
        if extra_args:
            s3_client.upload_fileobj(file_obj, bucket_name, s3_key, ExtraArgs=extra_args)
        else:
            s3_client.upload_fileobj(file_obj, bucket_name, s3_key)
        logger.info(f"Successfully uploaded file to s3://{bucket_name}/{s3_key}")
        return s3_key
    except ClientError as e:
        logger.error(f"S3 upload error: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error during S3 upload: {e}")
        raise



def generate_presigned_url(s3_key, expires_in=3600):
    """Generate a browser-accessible presigned download URL."""
    bucket_name = current_app.config.get("S3_BUCKET_NAME")

    # Use the public endpoint for URL generation if specified
    public_endpoint = current_app.config.get("AWS_PUBLIC_ENDPOINT_URL")
    s3_client = get_s3_client(public_endpoint)

    try:
        return s3_client.generate_presigned_url(
            "get_object",
            Params={"Bucket": bucket_name, "Key": s3_key},
            ExpiresIn=expires_in,
        )
    except ClientError as e:
        logger.error(
            "Failed to generate presigned URL for key %s: %s",
            s3_key,
            e,
        )
        return None


def delete_file_from_s3(s3_key):
    """Safely delete an object from S3 storage.
    
    Returns True if successfully deleted or already absent (NoSuchKey / 404).
    Re-raises on client/network failures to prevent leaving untracked orphaned objects.
    """
    if not s3_key:
        return True

    bucket_name = current_app.config.get("S3_BUCKET_NAME")
    s3_client = get_s3_client()

    try:
        s3_client.delete_object(Bucket=bucket_name, Key=s3_key)
        logger.info(f"Successfully deleted S3 object: s3://{bucket_name}/{s3_key}")
        return True
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code in ("NoSuchKey", "404"):
            logger.warning(f"S3 object {s3_key} already does not exist in bucket {bucket_name}")
            return True
        logger.error(f"ClientError deleting S3 object {s3_key}: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error deleting S3 object {s3_key}: {e}")
        raise
