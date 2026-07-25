"""Cleanup temp files, old logs, expired sessions."""

from datetime import datetime, timezone
from pathlib import Path

from app.tasks.celery_app import celery_app


@celery_app.task(bind=True, name="cleanup.run")
def run_cleanup(self):
    """
    Clean up temporary files, old logs, and expired data.
    """
    cleaned = {}
    now = datetime.now(timezone.utc)  # noqa: UP017

    # Clean temp files older than 24 hours
    temp_dir = Path("./storage/temp")
    if temp_dir.exists():
        cutoff = now.timestamp() - 86400
        removed = 0
        for f in temp_dir.iterdir():
            if f.is_file() and f.stat().st_mtime < cutoff:
                f.unlink()
                removed += 1
        cleaned["temp_files"] = removed

    # Clean old log files (older than 30 days)
    logs_dir = Path("./storage/logs")
    if logs_dir.exists():
        cutoff = now.timestamp() - (30 * 86400)
        removed = 0
        for f in logs_dir.glob("*.log"):
            if f.stat().st_mtime < cutoff:
                f.unlink()
                removed += 1
        cleaned["old_logs"] = removed

    # Clean expired exports
    exports_dir = Path("./storage/exports")
    if exports_dir.exists():
        cutoff = now.timestamp() - (7 * 86400)
        removed = 0
        for f in exports_dir.iterdir():
            if f.is_file() and f.stat().st_mtime < cutoff:
                f.unlink()
                removed += 1
        cleaned["old_exports"] = removed

    return {
        "cleaned": True,
        "items_removed": cleaned,
        "timestamp": now.isoformat(),
    }
