#!/bin/bash
# Cerberus AI — Database Backup Script
set -e

BACKUP_DIR="./database/postgres/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/cerberus_${TIMESTAMP}.sql.gz"

mkdir -p "$BACKUP_DIR"

echo "📦 Creating backup: $BACKUP_FILE"
docker-compose exec -T postgres pg_dump -U cerberus cerberus_db | gzip > "$BACKUP_FILE"

echo "✅ Backup created: $BACKUP_FILE ($(du -h "$BACKUP_FILE" | cut -f1))"

# Keep only last 30 backups
ls -t "$BACKUP_DIR"/cerberus_*.sql.gz | tail -n +31 | xargs -r rm
echo "🧹 Old backups cleaned up"
