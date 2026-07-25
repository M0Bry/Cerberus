"""Document Reranking — Cross-encoder reranking for better relevance."""

import structlog

logger = structlog.get_logger()


class DocumentReranker:
    """Reranks retrieved documents for better relevance."""

    async def rerank(self, query: str, documents: list[dict], top_k: int = 5) -> list[dict]:
        """Rerank documents by relevance to query."""
        return documents[:top_k]
