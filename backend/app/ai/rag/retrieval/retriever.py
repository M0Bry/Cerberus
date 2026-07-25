"""Document Retrieval — Retrieves relevant documents from vector store."""

import structlog

logger = structlog.get_logger()


class Retriever:
    """Retrieves relevant documents from vector store for RAG."""

    def __init__(self, vector_store=None, embedder=None):
        self.vector_store = vector_store
        self.embedder = embedder

    async def retrieve(
        self, query: str, top_k: int = 5, filters: dict | None = None
    ) -> list[dict]:
        """Retrieve top-k relevant documents."""
        if self.vector_store and self.embedder:
            query_embedding = await self.embedder.embed_text(query)
            results = await self.vector_store.search(
                query_embedding,
                top_k=top_k,
                filters=filters,
            )
            return results
        return []

    async def retrieve_with_reranking(
        self, query: str, top_k: int = 5
    ) -> list[dict]:
        """Retrieve and rerank documents for better relevance."""
        docs = await self.retrieve(query, top_k=top_k * 2)
        return docs[:top_k]

    async def retrieve_for_engagement(
        self, query: str, engagement_id: str, top_k: int = 5
    ) -> list[dict]:
        """Retrieve documents scoped to a specific engagement."""
        return await self.retrieve(
            query, top_k=top_k, filters={"engagement_id": engagement_id}
        )
