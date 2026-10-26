# S3 Bucket for Resource Files
resource "aws_s3_bucket" "resource_bucket" {
  bucket        = "${var.project_name}-resources-${var.environment}"
  force_destroy = false

  tags = {
    Name        = "${var.project_name}-resources"
    Environment = var.environment
  }
}

# Block All Public Access (Zero Public Access Guarantee)
resource "aws_s3_bucket_public_access_block" "block_public" {
  bucket = aws_s3_bucket.resource_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Server-Side Encryption by Default (AES256)
resource "aws_s3_bucket_server_side_encryption_configuration" "encryption" {
  bucket = aws_s3_bucket.resource_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Versioning Configuration for Data Protection
resource "aws_s3_bucket_versioning" "versioning" {
  bucket = aws_s3_bucket.resource_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}
