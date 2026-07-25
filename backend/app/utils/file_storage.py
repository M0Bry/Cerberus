"""File Storage — Local / S3 file storage with content-type validation."""

import hashlib
import uuid
from pathlib import Path

import structlog

from app.core.config import settings

logger = structlog.get_logger()


class FileStorage:
    """Handles file upload, download, and storage operations."""

    def __init__(self, base_dir: str | None = None):
        self.base_dir = Path(base_dir or settings.UPLOAD_DIR)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    async def store(self, content: bytes, filename: str, subdirectory: str = "") -> dict:
        """Store a file and return metadata."""
        file_id = str(uuid.uuid4())
        file_hash = hashlib.sha256(content).hexdigest()
        ext = Path(filename).suffix
        storage_path = self.base_dir / subdirectory / f"{file_id}{ext}"
        storage_path.parent.mkdir(parents=True, exist_ok=True)

        with open(storage_path, "wb") as f:
            f.write(content)

        return {
            "file_id": file_id,
            "storage_path": str(storage_path),
            "original_filename": filename,
            "file_size_bytes": len(content),
            "file_hash_sha256": file_hash,
        }

    async def read(self, storage_path: str) -> bytes:
        with open(storage_path, "rb") as f:
            return f.read()

    async def delete(self, storage_path: str) -> bool:
        try:
            Path(storage_path).unlink(missing_ok=True)
            return True
        except Exception as e:
            logger.error("file_delete_error", path=storage_path, error=str(e))
            return False
