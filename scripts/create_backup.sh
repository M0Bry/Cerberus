#!/bin/bash
set -e
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="./database/postgres/backups"
mkdir -p "$BACKUP_DIR"
docker-compose exec -T postgres pg_dump -U cerberus cerberus_db | gzip > "$BACKUP_DIR/cerberus_${TIMESTAMP}.sql.gz"
echo "✅ Backup created: $BACKUP_DIR/cerberus_${TIMESTAMP}.sql.gz"
