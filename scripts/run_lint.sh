#!/bin/bash
set -e
echo "Linting backend..."
cd backend && ruff check app/ --fix && black app/ && mypy app/ --ignore-missing-imports
echo "Linting frontend..."
cd ../frontend && npm run lint -- --fix
echo "✅ Linting complete"
