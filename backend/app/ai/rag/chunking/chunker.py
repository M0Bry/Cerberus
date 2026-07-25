"""Document Chunking — Splits documents into optimal chunks for embedding."""

import structlog

logger = structlog.get_logger()


class DocumentChunker:
    """Splits documents into chunks suitable for vector embedding."""

    def __init__(self, chunk_size: int = 1000, overlap: int = 200):
        self.chunk_size = chunk_size
        self.overlap = overlap

    def chunk_text(self, text: str, metadata: dict | None = None) -> list[dict]:
        """Split text into overlapping chunks."""
        chunks: list[dict] = []
        start = 0
        while start < len(text):
            end = min(start + self.chunk_size, len(text))
            chunk = text[start:end]
            chunks.append({
                "content": chunk,
                "metadata": metadata or {},
                "chunk_index": len(chunks),
                "start": start,
                "end": end,
            })
            start += self.chunk_size - self.overlap
        return chunks

    def chunk_documents(self, documents: list[dict]) -> list[dict]:
        """Chunk multiple documents."""
        all_chunks = []
        for doc in documents:
            chunks = self.chunk_text(doc.get("content", ""), doc.get("metadata"))
            all_chunks.extend(chunks)
        return all_chunks
