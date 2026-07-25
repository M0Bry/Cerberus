#!/bin/bash
set -e
echo "🛡️ Cerberus AI — Production Setup"
cp .env.example .env
echo "⚠️  Edit .env with production values before continuing."
docker-compose -f devops/docker/docker-compose.yml -f devops/docker/docker-compose.prod.yml build
docker-compose up -d
sleep 10
docker-compose exec backend alembic upgrade head
echo "✅ Production setup complete"
