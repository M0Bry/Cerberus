"""Vector memory for RAG (Retrieval-Augmented Generation)."""
class VectorMemory:
    async def add(self, documents: list): pass
    async def search(self, query: str, top_k: int = 5) -> list: return []
