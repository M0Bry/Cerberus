# Database — RDS PostgreSQL

resource "aws_db_subnet_group" "cerberus" {
  name       = "cerberus-db-subnet"
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_b.id]

  tags = { Name = "cerberus-db-subnet" }
}

resource "aws_security_group" "cerberus_db" {
  name        = "cerberus-db-sg"
  description = "Security group for Cerberus PostgreSQL"
  vpc_id      = aws_vpc.cerberus.id

  ingress {
    description     = "PostgreSQL from backend"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.cerberus_backend.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "cerberus-db-sg" }
}

resource "aws_db_instance" "cerberus" {
  identifier     = "cerberus-db"
  engine         = "postgres"
  engine_version = "16.3"
  instance_class = var.db_instance_class

  allocated_storage     = 20
  max_allocated_storage = 100
  storage_type          = "gp3"
  storage_encrypted     = true

  db_name  = var.db_name
  username = var.db_user
  password = var.db_password

  db_subnet_group_name   = aws_db_subnet_group.cerberus.name
  vpc_security_group_ids = [aws_security_group.cerberus_db.id]

  multi_az            = true
  publicly_accessible = false
  skip_final_snapshot = false

  backup_retention_period = 7
  backup_window           = "03:00-04:00"
  maintenance_window      = "Mon:04:00-Mon:05:00"

  tags = {
    Name        = "cerberus-db"
    Environment = var.environment
  }
}
