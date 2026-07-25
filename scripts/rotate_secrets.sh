#!/bin/bash
set -e
echo "Rotating secrets..."
python3 scripts/generate_keys.py > .env.new
echo "⚠️  Review .env.new and replace .env when ready"
echo "⚠️  Restart all services after rotation"
