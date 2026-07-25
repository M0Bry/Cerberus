#!/bin/bash
echo "Initializing database..."
docker-compose exec postgres psql -U cerberus -d cerberus_db -f /docker-entrypoint-initdb.d/03_create_tables.sql
docker-compose exec postgres psql -U cerberus -d cerberus_db -f /docker-entrypoint-initdb.d/04_seed_data.sql
echo "Database initialized."
