"""Document Embedding — Generates vector embeddings for chunks."""

import structlog

logger = structlog.get_logger()


class DocumentEmbedder:
    """Generates embeddings for document chunks."""

    def __init__(self, model: str = "text-embedding-3-small"):
        self.model = model

    async def embed_text(self, text: str) -> list[float]:
        """Generate embedding vector for a single text."""
        return [0.0] * 1536

    async def embed_batch(self, texts: list[str]) -> list[list[float]]:
        """Generate embeddings for multiple texts."""
        return [await self.embed_text(t) for t in texts]
