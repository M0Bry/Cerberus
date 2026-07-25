"""Conversation Memory — Redis-backed conversation memory with buffer + summary."""

import json

import structlog

logger = structlog.get_logger()


class ConversationMemory:
    """Manages conversation history with Redis-backed persistence and context windowing."""

    def __init__(self, redis_client=None, max_messages: int = 50, summary_threshold: int = 30):
        self.redis = redis_client
        self.max_messages = max_messages
        self.summary_threshold = summary_threshold

    async def add_message(
        self,
        session_id: str,
        role: str,
        content: str,
        metadata: dict | None = None,
    ):
        key = f"chat:{session_id}:messages"
        message = {"role": role, "content": content, "metadata": metadata or {}}
        if self.redis:
            await self.redis.rpush(key, json.dumps(message))
            await self.redis.ltrim(key, -self.max_messages, -1)
            await self.redis.expire(key, 1800)

    async def get_messages(
        self, session_id: str, limit: int | None = None
    ) -> list[dict]:
        key = f"chat:{session_id}:messages"
        if self.redis:
            raw = await self.redis.lrange(key, 0, limit or -1)
            return [json.loads(m) for m in raw]
        return []

    async def get_context_window(
        self, session_id: str, max_tokens: int = 8000
    ) -> list[dict]:
        messages = await self.get_messages(session_id)
        total = 0
        result: list[dict] = []
        for msg in reversed(messages):
            est_tokens = len(msg["content"]) // 4
            if total + est_tokens > max_tokens:
                break
            result.insert(0, msg)
            total += est_tokens
        return result

    async def clear(self, session_id: str):
        if self.redis:
            await self.redis.delete(f"chat:{session_id}:messages")
