#!/bin/bash
set -e
echo "Running Alembic migrations..."
cd backend && alembic upgrade head
echo "✅ Migrations complete"
