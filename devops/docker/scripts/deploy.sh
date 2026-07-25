#!/bin/bash
# Cerberus AI — Production Deployment Script
set -e

echo "🛡️  Cerberus AI — Production Deployment"
echo "========================================"

# Pull latest changes
git pull origin main

# Build images
docker-compose -f devops/docker/docker-compose.yml -f devops/docker/docker-compose.prod.yml build

# Run migrations
docker-compose exec backend alembic upgrade head

# Restart services
docker-compose -f devops/docker/docker-compose.yml -f devops/docker/docker-compose.prod.yml up -d

# Health check
sleep 10
curl -f http://localhost:8000/health || echo "⚠️  Health check failed!"

echo "✅ Deployment complete!"
