# VPC — Networking infrastructure

resource "aws_vpc" "cerberus" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "cerberus-vpc"
    Environment = var.environment
    Project     = "CerberusAI"
  }
}

resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.cerberus.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 1)
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = { Name = "cerberus-public-a" }
}

resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.cerberus.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 2)
  availability_zone       = "${var.aws_region}b"
  map_public_ip_on_launch = true

  tags = { Name = "cerberus-public-b" }
}

resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.cerberus.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, 10)
  availability_zone = "${var.aws_region}a"

  tags = { Name = "cerberus-private-a" }
}

resource "aws_subnet" "private_b" {
  vpc_id            = aws_vpc.cerberus.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, 11)
  availability_zone = "${var.aws_region}b"

  tags = { Name = "cerberus-private-b" }
}

resource "aws_internet_gateway" "cerberus" {
  vpc_id = aws_vpc.cerberus.id
  tags   = { Name = "cerberus-igw" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.cerberus.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.cerberus.id
  }

  tags = { Name = "cerberus-public-rt" }
}

resource "aws_route_table_association" "public_a" {
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_b" {
  subnet_id      = aws_subnet.public_b.id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "cerberus_backend" {
  name        = "cerberus-backend-sg"
  description = "Security group for Cerberus backend services"
  vpc_id      = aws_vpc.cerberus.id

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Backend API"
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "cerberus-backend-sg" }
}
