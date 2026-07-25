#!/bin/bash
BACKUP_FILE=${1:?"Usage: restore-db.sh <backup_file>"}
echo "Restoring from $BACKUP_FILE..."
gunzip -c "$BACKUP_FILE" | docker-compose exec -T postgres psql -U cerberus -d cerberus_db
echo "Restore complete."
