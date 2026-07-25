"""Automated database backup to S3 / local storage."""

import subprocess
from datetime import datetime, timezone
from pathlib import Path

from app.tasks.celery_app import celery_app


@celery_app.task(bind=True, name="backup.database")
def run_database_backup(self):
    """
    Create a database backup.

    Uses pg_dump for PostgreSQL backup and stores locally.
    In production: upload to S3.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")  # noqa: UP017
    backup_dir = Path("./database/postgres/backups")
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup_file = backup_dir / f"cerberus_{timestamp}.sql.gz"

    try:
        # In production: use actual pg_dump with connection string
        # For now, create a placeholder that indicates backup was attempted
        result = subprocess.run(
            ["pg_dump", "-U", "cerberus", "cerberus_db"],
            capture_output=True,
            timeout=300,
        )
        if result.returncode == 0:
            import gzip

            with gzip.open(backup_file, "wb") as f:
                f.write(result.stdout)
            return {
                "backup_id": timestamp,
                "status": "completed",
                "file": str(backup_file),
                "size_bytes": backup_file.stat().st_size,
            }
        else:
            return {
                "backup_id": timestamp,
                "status": "failed",
                "error": result.stderr.decode()[:500],
            }
    except FileNotFoundError:
        # pg_dump not available — create placeholder backup record
        return {
            "backup_id": timestamp,
            "status": "skipped",
            "reason": "pg_dump not installed",
        }
    except Exception as e:
        return {
            "backup_id": timestamp,
            "status": "failed",
            "error": str(e),
        }
