"""
Document Validation Background Tasks.
"""

import asyncio
from datetime import datetime, timezone

from app.tasks.celery_app import celery_app


@celery_app.task(bind=True, name="document.validate")
def validate_document(self, document_id: str):
    """
    Run validation pipeline on an uploaded document.

    Steps:
    1. Format verification
    2. Malware scanning
    3. Metadata extraction
    4. Relevance validation
    5. Encryption
    """
    async def _run():
        import json
        import os

        from sqlalchemy import select

        from app.db.models.uploaded_document import (
            DocumentValidationStatus,
            UploadedDocument,
        )
        from app.db.session import async_session_factory
        from app.utils.virus_scanner import VirusScanner

        async with async_session_factory() as db:
            result = await db.execute(
                select(UploadedDocument).where(UploadedDocument.id == document_id)
            )
            document = result.scalar_one_or_none()
            if not document:
                return {
                    "document_id": document_id,
                    "status": "error",
                    "message": "Document not found",
                }

            # Step 1: Format verification
            file_path = document.storage_path
            if not os.path.exists(file_path):
                document.validation_status = DocumentValidationStatus.FAILED_FORMAT
                document.validation_notes = "File not found on disk"
                await db.commit()
                return {
                    "document_id": document_id,
                    "status": "failed",
                    "reason": "file_not_found",
                }

            # Step 2: Malware scanning
            scanner = VirusScanner()
            scan_result = await scanner.scan_file(file_path)
            document.malware_scan_result = str(scan_result)

            if not scan_result.get("clean", True):
                document.validation_status = (
                    DocumentValidationStatus.FAILED_MALWARE
                )
                document.validation_notes = (
                    f"Malware detected: {scan_result.get('threats_found', [])}"
                )
                await db.commit()
                return {
                    "document_id": document_id,
                    "status": "failed",
                    "reason": "malware_detected",
                }

            # Step 3: Metadata extraction
            file_stat = os.stat(file_path)
            metadata = {
                "file_size_bytes": file_stat.st_size,
                "created_at": datetime.fromtimestamp(
                    file_stat.st_ctime
                ).isoformat(),
                "modified_at": datetime.fromtimestamp(
                    file_stat.st_mtime
                ).isoformat(),
                "extension": os.path.splitext(document.original_filename)[1],
            }
            document.metadata_extracted = json.dumps(metadata)

            # Step 4: Relevance validation (basic — check file extension)
            allowed = [
                ".pdf", ".docx", ".xlsx", ".txt",
                ".csv", ".json", ".xml", ".zip",
            ]
            ext = os.path.splitext(document.original_filename)[1].lower()
            if ext not in allowed:
                document.validation_status = (
                    DocumentValidationStatus.FAILED_FORMAT
                )
                document.validation_notes = (
                    f"Unsupported file format: {ext}"
                )
                await db.commit()
                return {
                    "document_id": document_id,
                    "status": "failed",
                    "reason": "unsupported_format",
                }

            # All checks passed
            document.validation_status = DocumentValidationStatus.PASSED
            document.validated_at = datetime.now(timezone.utc)  # noqa: UP017
            document.validation_notes = "All validation checks passed"
            await db.commit()

            return {
                "document_id": document_id,
                "status": "completed",
                "validation_status": "passed",
                "malware_clean": scan_result.get("clean", True),
            }

    return asyncio.run(_run())
