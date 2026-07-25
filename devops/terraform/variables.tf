variable "aws_region" { default = "us-east-1" }
variable "environment" { default = "production" }
variable "db_password" { sensitive = true }
variable "domain" { default = "cerberus-ai.com" }
