output "ec2_public_ip" {
  description = "Public IPv4 address of the EC2 web application host"
  value       = aws_instance.web.public_ip
}

output "ecr_repository_url" {
  description = "URL of the Amazon ECR container repository"
  value       = aws_ecr_repository.app_repo.repository_url
}

output "rds_endpoint" {
  description = "Connection endpoint of the PostgreSQL RDS instance (private subnet)"
  value       = aws_db_instance.postgres.endpoint
}

output "rds_database_name" {
  description = "Name of the default PostgreSQL database"
  value       = aws_db_instance.postgres.db_name
}

output "s3_bucket_name" {
  description = "Name of the dedicated private S3 storage bucket"
  value       = aws_s3_bucket.resource_bucket.bucket
}

output "s3_bucket_arn" {
  description = "ARN of the private S3 storage bucket"
  value       = aws_s3_bucket.resource_bucket.arn
}
