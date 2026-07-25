"""Redis-based rate limiting (per IP, per user, per endpoint)."""

import structlog

logger = structlog.get_logger()


class RedisRateLimiter:
    def __init__(self, redis_client=None):
        self.redis = redis_client

    async def check(self, key: str, limit: int, window: int = 60) -> dict:
        if self.redis:
            current = await self.redis.incr(f"rate_limit:{key}")
            if current == 1:
                await self.redis.expire(f"rate_limit:{key}", window)
            return {
                "allowed": current <= limit,
                "remaining": max(0, limit - current),
                "limit": limit,
            }
        return {"allowed": True, "remaining": limit, "limit": limit}
