# DB Subnet Group spanning private subnets in at least two AZs
resource "aws_db_subnet_group" "rds_subnet_group" {
  name        = "${var.project_name}-rds-subnet-group"
  description = "Private DB subnet group for RDS PostgreSQL"
  subnet_ids  = [aws_subnet.private_1.id, aws_subnet.private_2.id]

  tags = {
    Name = "${var.project_name}-rds-subnet-group"
  }
}

variable "db_password" {
  type        = string
  description = "Master password for PostgreSQL database"
  sensitive   = true
  default     = "CloudOpsSentinel2026SecurePass!"
}

variable "db_username" {
  type        = string
  description = "Master username for PostgreSQL database"
  default     = "sentinel_admin"
}

# Managed AWS RDS PostgreSQL Instance (Single-AZ, db.t3.micro)
resource "aws_db_instance" "postgres" {
  identifier        = "${var.project_name}-postgres"
  engine            = "postgres"
  engine_version     = "15.7"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  max_allocated_storage = 50
  storage_type      = "gp3"

  db_name  = "resource_exchange"
  username = var.db_username
  password = var.db_password

  db_subnet_group_name   = aws_db_subnet_group.rds_subnet_group.name
  vpc_security_group_ids = [aws_security_group.rds.id]

  # Strictly not publicly accessible
  publicly_accessible = false
  multi_az            = false

  skip_final_snapshot       = true
  deletion_protection       = false
  auto_minor_version_upgrade = true

  tags = {
    Name = "${var.project_name}-postgres"
  }
}
