"""
Redis-based rate limiting (per IP, per user, per endpoint).

بيوفر:
- Fixed Window و Sliding Window
- Per-IP, per-user, per-endpoint
- Atomic operations باستخدام Lua Script
- Fail-Open لو Redis وقع
- Reset و get_status
- Retry-After
"""

import time
from typing import Optional, Tuple

import redis.asyncio as redis
import structlog

from app.core.config import settings
from app.core.inmemory_store import SlidingWindowCounter

logger = structlog.get_logger()

# How often (seconds) we retry connecting to Redis after a failure.
_RECONNECT_INTERVAL = 15.0


class RedisRateLimiter:
    """
    كلاس للـ Rate Limiting باستخدام Redis.

    بيدعم:
    - Fixed Window: عداد بيترجع صفر كل window.
    - Sliding Window: بيستخدم Sorted Set عشان يمنع الـ burst.
    """

    # Lua Script للـ Sliding Window (atomic)
    _SLIDING_WINDOW_SCRIPT = """
    local key = KEYS[1]
    local now = tonumber(ARGV[1])
    local window = tonumber(ARGV[2])
    local limit = tonumber(ARGV[3])
    local member = ARGV[4]

    -- امسح الطلبات القديمة
    redis.call('ZREMRANGEBYSCORE', key, 0, now - window)

    -- عدد الطلبات الحالية
    local count = redis.call('ZCARD', key)

    if count < limit then
        -- ضيف الطلب الحالي
        redis.call('ZADD', key, now, member)
        redis.call('EXPIRE', key, window)
        return {1, limit - count - 1, limit}
    else
        return {0, 0, limit}
    end
    """

    # Lua Script للـ Fixed Window (atomic)
    _FIXED_WINDOW_SCRIPT = """
    local key = KEYS[1]
    local limit = tonumber(ARGV[1])
    local window = tonumber(ARGV[2])

    local current = redis.call('INCR', key)
    if current == 1 then
        redis.call('EXPIRE', key, window)
    end

    if current <= limit then
        return {1, limit - current, limit}
    else
        return {0, 0, limit}
    end
    """

    def __init__(self, redis_client: Optional[redis.Redis] = None):
        self.redis = redis_client
        # In-memory fallback so rate limiting still works without Redis.
        self._fallback = SlidingWindowCounter()
        self._last_redis_attempt = 0.0

    # ─── Internal ──────────────────────────────────────────

    async def _ensure_redis(self) -> Optional[redis.Redis]:
        """
        Try to connect to Redis lazily (throttled).

        If a client was provided, use it. Otherwise attempt to build one
        from settings at most once every _RECONNECT_INTERVAL seconds.
        Returns the client or None if unavailable.
        """
        if self.redis is not None:
            return self.redis

        now = time.time()
        if now - self._last_redis_attempt < _RECONNECT_INTERVAL:
            return None
        self._last_redis_attempt = now

        try:
            client = redis.from_url(
                settings.REDIS_URL,
                decode_responses=True,
                socket_connect_timeout=2,
                socket_timeout=2,
            )
            await client.ping()
            self.redis = client
            logger.info("rate_limiter_redis_connected")
            return client
        except Exception as e:
            logger.warning("rate_limiter_redis_unavailable", error=str(e))
            return None

    def _build_key(self, identifier: str, scope: str = "ip", endpoint: str = "") -> str:
        """
        بتبني الـ Redis key.
        
        Examples:
            _build_key("192.168.1.1", "ip", "/api/v1/auth")
            → "rate_limit:ip:192.168.1.1:/api/v1/auth"
        """
        parts = ["rate_limit", scope, identifier]
        if endpoint:
            parts.append(endpoint)
        return ":".join(parts)

    # ─── Public API ────────────────────────────────────────

    async def check(
        self,
        identifier: str,
        limit: Optional[int] = None,
        window: Optional[int] = None,
        scope: str = "ip",
        endpoint: str = "",
        algorithm: str = "sliding",
    ) -> dict:
        """
        بيفحص معدل الطلبات.

        Args:
            identifier: IP أو user_id
            limit: عدد الطلبات (default من settings)
            window: النافذة الزمنية (default من settings)
            scope: "ip" أو "user" أو "endpoint"
            endpoint: المسار (اختياري)
            algorithm: "sliding" أو "fixed"

        Returns:
            dict فيه:
            - allowed: bool
            - remaining: int
            - limit: int
            - retry_after: int (لو allowed=False)
        """
        limit = limit or settings.DEFENSE_RATE_LIMIT
        window = window or settings.DEFENSE_RATE_WINDOW

        key = self._build_key(identifier, scope, endpoint)
        now = time.time()
        member = f"{now}:{id(now)}"

        client = await self._ensure_redis()
        if client is None:
            # No Redis — enforce with the in-memory fallback so the
            # limiter is never silently disabled.
            result = self._fallback.check(key, limit, window)
            if not result["allowed"]:
                logger.warning(
                    "rate_limit_exceeded",
                    identifier=identifier,
                    scope=scope,
                    endpoint=endpoint,
                    limit=limit,
                    backend="memory",
                )
            return result

        try:
            if algorithm == "sliding":
                result = await client.eval(
                    self._SLIDING_WINDOW_SCRIPT,
                    1,
                    key,
                    now,
                    window,
                    limit,
                    member,
                )
            else:
                result = await client.eval(
                    self._FIXED_WINDOW_SCRIPT,
                    1,
                    key,
                    limit,
                    window,
                )

            allowed = bool(result[0])
            remaining = int(result[1])
            limit_val = int(result[2])

            response = {
                "allowed": allowed,
                "remaining": remaining,
                "limit": limit_val,
                "retry_after": 0,
            }

            if not allowed:
                response["retry_after"] = window
                logger.warning(
                    "rate_limit_exceeded",
                    identifier=identifier,
                    scope=scope,
                    endpoint=endpoint,
                    limit=limit_val,
                )

            return response

        except Exception as e:
            # Redis error mid-call — degrade to the in-memory limiter
            # (fail-closed for limiting, not for availability).
            logger.error("rate_limiter_error", error=str(e), identifier=identifier)
            result = self._fallback.check(key, limit, window)
            if not result["allowed"]:
                logger.warning(
                    "rate_limit_exceeded",
                    identifier=identifier,
                    scope=scope,
                    endpoint=endpoint,
                    limit=limit,
                    backend="memory",
                )
            return result

    async def get_status(
        self,
        identifier: str,
        scope: str = "ip",
        endpoint: str = "",
        limit: Optional[int] = None,
    ) -> dict:
        """
        بترجع حالة العداد من غير ما تزوده.
        """
        limit = limit or settings.DEFENSE_RATE_LIMIT

        key = self._build_key(identifier, scope, endpoint)

        if self.redis is None:
            current = self._fallback.count(key, settings.DEFENSE_RATE_WINDOW)
            return {
                "current": current,
                "limit": limit,
                "remaining": max(0, limit - current),
            }

        try:
            current = await self.redis.zcard(key)
            return {
                "current": current,
                "limit": limit,
                "remaining": max(0, limit - current),
            }
        except Exception as e:
            logger.error("rate_limiter_status_error", error=str(e))
            current = self._fallback.count(key, settings.DEFENSE_RATE_WINDOW)
            return {
                "current": current,
                "limit": limit,
                "remaining": max(0, limit - current),
            }

    async def reset(
        self,
        identifier: str,
        scope: str = "ip",
        endpoint: str = "",
    ) -> None:
        """
        بتعيد تعيين العداد لـ identifier معين.
        """
        key = self._build_key(identifier, scope, endpoint)

        if self.redis is None:
            self._fallback.clear(key)
            return

        try:
            await self.redis.delete(key)
            self._fallback.clear(key)
            logger.info(
                "rate_limit_reset",
                identifier=identifier,
                scope=scope,
                endpoint=endpoint,
            )
        except Exception as e:
            logger.error("rate_limiter_reset_error", error=str(e))