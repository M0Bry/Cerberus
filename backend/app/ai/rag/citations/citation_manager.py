"""Citation Manager — Tracks and formats citations for AI responses."""

import structlog

logger = structlog.get_logger()


class CitationManager:
    """Manages citations and source attribution."""

    def add_citations(self, response: str, sources: list[dict]) -> str:
        """Add citation markers to response text."""
        if not sources:
            return response
        citations = "\n\n**Sources:**\n"
        for i, src in enumerate(sources, 1):
            metadata = src.get("metadata", {})
            url = metadata.get("url") or metadata.get("source", "Unknown")
            citations += f"[{i}] {url}\n"
        return response + citations
