#!/bin/bash
# Cerberus AI — Development Environment Setup
set -e

echo "🛡️  Cerberus AI — Dev Setup"
echo "============================"

# Backend
echo "📦 Setting up backend..."
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cd ..

# Frontend
echo "📦 Setting up frontend..."
cd frontend
npm install
cd ..

# Environment files
[ ! -f backend/.env ] && cp backend/.env.example backend/.env
[ ! -f frontend/.env ] && cp frontend/.env.example frontend/.env

# Create directories
mkdir -p backend/uploads backend/reports

echo ""
echo "✅ Setup complete!"
echo ""
echo "Run 'make dev' to start with Docker"
echo "Or run 'make dev-backend' + 'make dev-frontend' separately"
