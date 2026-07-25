#!/bin/bash
set -e
echo "Running backend tests..."
cd backend && python -m pytest tests/ -v --cov=app --cov-report=html
echo "Running frontend tests..."
cd ../frontend && npm test -- --coverage
echo "✅ All tests passed"
