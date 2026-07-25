provider "aws" {
  region = var.aws_region
  default_tags {
    tags = { Project = "CerberusAI", Environment = var.environment, ManagedBy = "Terraform" }
  }
}
