# Compute — ECS / EC2 instances for backend, frontend, workers

resource "aws_ecs_cluster" "cerberus" {
  name = "cerberus-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Environment = var.environment
    Project     = "CerberusAI"
  }
}

resource "aws_ecs_task_definition" "backend" {
  family                   = "cerberus-backend"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([{
    name      = "backend"
    image     = "${var.ecr_repository}/cerberus-backend:latest"
    essential = true
    portMappings = [{ containerPort = 8000, protocol = "tcp" }]
    environment = [
      { name = "ENVIRONMENT", value = var.environment },
      { name = "DATABASE_URL", value = "postgresql+asyncpg://${var.db_user}:${var.db_password}@${aws_db_instance.cerberus.address}:5432/${var.db_name}" },
      { name = "REDIS_URL", value = "redis://:${var.redis_password}@${aws_elasticache_cluster.cerberus.cache_nodes[0].address}:6379/0" },
    ]
    secrets = [
      { name = "SECRET_KEY", valueFrom = aws_secretsmanager_secret.secret_key.arn },
      { name = "OPENAI_API_KEY", valueFrom = aws_secretsmanager_secret.openai_key.arn },
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = "/ecs/cerberus-backend"
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = "backend"
      }
    }
  }])
}

resource "aws_ecs_service" "backend" {
  name            = "cerberus-backend"
  cluster         = aws_ecs_cluster.cerberus.id
  task_definition = aws_ecs_task_definition.backend.arn
  desired_count   = 2
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = [aws_subnet.private_a.id, aws_subnet.private_b.id]
    security_groups  = [aws_security_group.cerberus_backend.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.backend.arn
    container_name   = "backend"
    container_port   = 8000
  }
}

resource "aws_iam_role" "ecs_execution" {
  name = "cerberus-ecs-execution"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role" "ecs_task" {
  name = "cerberus-ecs-task"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_cloudwatch_log_group" "backend" {
  name              = "/ecs/cerberus-backend"
  retention_in_days = 30
}
