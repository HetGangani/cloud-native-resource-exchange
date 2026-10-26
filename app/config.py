import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-prod")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

    # AWS / S3 Configuration
    S3_BUCKET_NAME = os.getenv("S3_BUCKET_NAME", "cloudops-sentinel-resources")
    AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
    AWS_ENDPOINT_URL = os.getenv("AWS_ENDPOINT_URL", None)
    AWS_PUBLIC_ENDPOINT_URL = os.getenv(
    "AWS_PUBLIC_ENDPOINT_URL",
    AWS_ENDPOINT_URL
    )

    # Simplified Admin Auth Configuration
    ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")
    ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@sentinel.local")
    JWT_EXPIRATION_HOURS = int(os.getenv("JWT_EXPIRATION_HOURS", "24"))