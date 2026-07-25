# Redis — ElastiCache cluster

resource "aws_elasticache_subnet_group" "cerberus" {
  name       = "cerberus-redis-subnet"
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_b.id]
}

resource "aws_security_group" "cerberus_redis" {
  name        = "cerberus-redis-sg"
  description = "Security group for Cerberus Redis"
  vpc_id      = aws_vpc.cerberus.id

  ingress {
    description     = "Redis from backend"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.cerberus_backend.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_elasticache_cluster" "cerberus" {
  cluster_id           = "cerberus-redis"
  engine               = "redis"
  engine_version       = "7.0"
  node_type            = "cache.t3.micro"
  num_cache_nodes      = 1
  parameter_group_name = "default.redis7"
  port                 = 6379
  security_group_ids   = [aws_security_group.cerberus_redis.id]
  subnet_group_name    = aws_elasticache_subnet_group.cerberus.name

  tags = {
    Name        = "cerberus-redis"
    Environment = var.environment
  }
}
