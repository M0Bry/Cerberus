"""
Engagement Memory — Per-engagement memory isolation.
"""

import json

import structlog

logger = structlog.get_logger()


class EngagementMemory:
    """Isolates memory per engagement to prevent data leakage between clients."""

    def __init__(self, redis_client=None):
        self.redis = redis_client

    async def store(self, engagement_id: str, key: str, value: dict):
        if self.redis:
            full_key = f"engagement:{engagement_id}:memory:{key}"
            await self.redis.set(full_key, json.dumps(value), ex=86400)

    async def retrieve(self, engagement_id: str, key: str) -> dict:
        if self.redis:
            full_key = f"engagement:{engagement_id}:memory:{key}"
            data = await self.redis.get(full_key)
            return json.loads(data) if data else {}
        return {}

    async def clear(self, engagement_id: str):
        if self.redis:
            pattern = f"engagement:{engagement_id}:memory:*"
            keys = await self.redis.keys(pattern)
            if keys:
                await self.redis.delete(*keys)
