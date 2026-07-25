"""
Context Manager — Context compression, token counting, truncation.
"""

import structlog

logger = structlog.get_logger()


class ContextManager:
    """Manages AI context windows, compression, and token counting."""

    def __init__(self, max_tokens: int = 8000):
        self.max_tokens = max_tokens

    def count_tokens(self, text: str) -> int:
        """Estimate token count (rough: ~4 chars per token)."""
        return len(text) // 4

    def truncate_messages(self, messages: list[dict]) -> list[dict]:
        """Truncate messages to fit within token budget."""
        total = 0
        result: list[dict] = []          # ← Added type annotation
        for msg in reversed(messages):
            tokens = self.count_tokens(msg.get("content", ""))
            if total + tokens > self.max_tokens:
                break
            result.insert(0, msg)
            total += tokens
        return result

    def compress_context(self, messages: list[dict]) -> str:
        """Compress conversation history into a summary string."""
        lines = []
        for msg in messages[-10:]:
            role = msg.get("role", "unknown")
            content = msg.get("content", "")[:200]
            lines.append(f"[{role}]: {content}")
        return "\n".join(lines)
