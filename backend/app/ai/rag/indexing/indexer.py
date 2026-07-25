"""Document Indexing — Stores embeddings in vector database."""

import structlog

logger = structlog.get_logger()


class DocumentIndexer:
    """Indexes document chunks with embeddings into vector store."""

    async def index_chunks(
        self, chunks: list[dict], embeddings: list[list[float]]
    ) -> list[str]:
        """Index chunks with their embeddings."""
        ids = []
        for i, (chunk, _embedding) in enumerate(
            zip(chunks, embeddings, strict=True)
        ):
            doc_id = f"doc_{i}_{hash(chunk.get("content", "")[:50])}"
            ids.append(doc_id)
        logger.info("indexed_chunks", count=len(ids))
        return ids

    async def delete_by_engagement(self, engagement_id: str) -> int:
        """Delete all indexed chunks for an engagement."""
        return 0
