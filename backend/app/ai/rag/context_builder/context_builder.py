"""Context Builder — Assembles retrieved documents into context for LLM."""

import structlog

logger = structlog.get_logger()


class ContextBuilder:
    """Builds context from retrieved documents for LLM prompts."""

    def build_context(self, documents: list[dict], max_tokens: int = 4000) -> str:
        """Build context string from documents, respecting token limit."""
        context_parts = []
        total_tokens = 0
        for doc in documents:
            content = doc.get("content", "")
            tokens = len(content) // 4
            if total_tokens + tokens > max_tokens:
                break
            source = doc.get("metadata", {}).get("source", "unknown")
            context_parts.append(f"[Source: {source}]\n{content}")
            total_tokens += tokens
        return "\n\n---\n\n".join(context_parts)
