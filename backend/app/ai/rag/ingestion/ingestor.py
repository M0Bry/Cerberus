"""Document Ingestion — Loads and preprocesses documents for RAG."""

import structlog

logger = structlog.get_logger()


class DocumentIngestor:
    """Ingests documents from various sources into the RAG pipeline."""

    async def ingest_text(self, text: str, metadata: dict | None = None) -> list[dict]:
        """Ingest raw text content."""
        return [{"content": text, "metadata": metadata or {}, "source": "text"}]

    async def ingest_file(self, file_path: str) -> list[dict]:
        """Ingest a file (PDF, DOCX, TXT)."""
        logger.info("ingesting_file", path=file_path)
        return [{"content": "", "metadata": {"path": file_path}, "source": "file"}]

    async def ingest_url(self, url: str) -> list[dict]:
        """Ingest content from a URL."""
        logger.info("ingesting_url", url=url)
        return [{"content": "", "metadata": {"url": url}, "source": "url"}]
