#!/bin/bash
# Cerberus AI — Quick Setup Script

set -e

echo "🛡️  Cerberus AI — Setup"
echo "========================"
echo ""

# Copy environment files
if [ ! -f backend/.env ]; then
    cp backend/.env.example backend/.env
    echo "✅ Created backend/.env from example"
fi

if [ ! -f frontend/.env ]; then
    cp frontend/.env.example frontend/.env
    echo "✅ Created frontend/.env from example"
fi

# Create necessary directories
mkdir -p backend/uploads backend/reports
touch backend/uploads/.gitkeep backend/reports/.gitkeep

echo ""
echo "📋 Next steps:"
echo "  1. Edit backend/.env with your settings"
echo "  2. Run: docker-compose up -d"
echo "  3. Run: docker-compose exec backend alembic upgrade head"
echo "  4. Visit: http://localhost:3000"
echo ""
echo "🛡️  Cerberus AI is ready to deploy!"
