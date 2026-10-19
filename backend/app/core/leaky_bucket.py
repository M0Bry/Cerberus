"""
Leaky Bucket Rate Limiter — Redis-backed.

بيوفر:
- Leaky Bucket algorithm
- Traffic shaping (smooth out bursts)
- Queue-based
- Distributed (Redis-backed)
- Atomic operations (Lua Script)

الفرق بينه وبين Token Bucket:
- Token Bucket: بيسمح بـ burst
- Leaky Bucket: بيعمل smoothing للطلبات

مثال:
- Token Bucket: لو عندك 100 توكن، ممكن تبعت 100 في ثانية
- Leaky Bucket: الـ 100 بيخرجوا بمعدل ثابت (مثلاً 10/ثانية)

الاستخدام:
- APIs بتحتاج traffic shaping
- حماية الخدمات الحساسة
"""

import time
from typing import Any, Dict, Optional

import redis.asyncio as redis
import structlog

from app.core.config import settings

logger = structlog.get_logger()


class LeakyBucket:
    """
    Leaky Bucket Rate Limiter.

    الفكرة:
    - Bucket له capacity (أقصى عدد طلبات في الـ queue)
    - Leak rate (معدل خروج الطلبات)
    - كل request بتدخل الـ queue
    - لو الـ queue مليان → reject

    الـ Lua Script:
    1. احسب الـ leak اللي حصل
    2. لو الـ queue فيه مساحة → ضيف
    3. لو مليان → reject
    """

    _redis_client: Optional[redis.Redis] = None

    # ─── Lua Script ─────────────────────────────────────────
    _LEAKY_BUCKET_SCRIPT = """
    local key = KEYS[1]
    local capacity = tonumber(ARGV[1])
    local leak_rate = tonumber(ARGV[2])
    local now = tonumber(ARGV[3])
    local requested = tonumber(ARGV[4])
    local ttl = tonumber(ARGV[5])

    -- 1. جيب الحالة الحالية
    local data = redis.call('HMGET', key, 'level', 'last_leak')
    local level = tonumber(data[1])  -- عدد الطلبات في الـ bucket
    local last_leak = tonumber(data[2])

    -- 2. لو أول مرة → ابدأ فاضي
    if level == nil then
        level = 0
        last_leak = now
    end

    -- 3. احسب الـ leak
    local time_passed = now - last_leak
    if time_passed > 0 then
        local leaked = time_passed * leak_rate
        level = math.max(0, level - leaked)
        last_leak = now
    end

    -- 4. فحص لو فيه مساحة
    local allowed = false
    local remaining = math.max(0, capacity - level)

    if level + requested <= capacity then
        level = level + requested
        allowed = true
        remaining = math.max(0, capacity - level)
    end

    -- 5. احفظ الحالة
    redis.call('HMSET', key,
        'level', level,
        'last_leak', last_leak,
        'leak_rate', leak_rate,
        'capacity', capacity
    )
    redis.call('EXPIRE', key, ttl)

    -- 6. احسب retry_after
    local retry_after = 0
    if not allowed then
        local needed = (level + requested) - capacity
        retry_after = math.ceil(needed / leak_rate)
    end

    return {allowed and 1 or 0, math.floor(remaining), retry_after, math.floor(level)}
    """

    # ─── Internal ──────────────────────────────────────────

    @classmethod
    def get_client(cls) -> Optional[redis.Redis]:
        """Lazy Redis client."""
        if cls._redis_client is None:
            try:
                cls._redis_client = redis.from_url(
                    settings.REDIS_URL,
                    decode_responses=True,
                    socket_connect_timeout=5,
                    socket_timeout=5,
                )
            except Exception as e:
                logger.error("leaky_bucket_redis_init_failed", error=str(e))
                return None
        return cls._redis_client

    @staticmethod
    def _build_key(identifier: str, scope: str = "ip", endpoint: str = "") -> str:
        """بتبني الـ Redis key."""
        parts = ["leaky_bucket", scope, identifier]
        if endpoint:
            parts.append(endpoint)
        return ":".join(parts)

    # ─── Main API ──────────────────────────────────────────

    @classmethod
    async def check(
        cls,
        identifier: str,
        capacity: Optional[int] = None,
        leak_rate: Optional[float] = None,
        scope: str = "ip",
        endpoint: str = "",
        requested: int = 1,
    ) -> Dict[str, Any]:
        """
        بيفحص لو الطلب مسموح.

        Args:
            identifier: IP أو user_id
            capacity: أقصى عدد في الـ queue (default: DEFENSE_RATE_LIMIT)
            leak_rate: معدل التسريب (طلب/ثانية)
            scope: "ip" / "user" / "endpoint"
            endpoint: المسار (اختياري)
            requested: عدد الطلبات

        Returns:
            dict فيه:
            - allowed: bool
            - remaining: المساحة المتبقية
            - limit: capacity
            - retry_after: ثواني للانتظار
            - level: مستوى الـ bucket الحالي
            - algorithm: "leaky_bucket"
        """
        capacity = capacity or settings.DEFENSE_RATE_LIMIT
        leak_rate = leak_rate or (capacity / settings.DEFENSE_RATE_WINDOW)

        client = cls.get_client()
        if not client:
            # Fail-Open
            return {
                "allowed": True,
                "remaining": capacity,
                "limit": capacity,
                "retry_after": 0,
                "level": 0,
                "algorithm": "leaky_bucket",
            }

        key = cls._build_key(identifier, scope, endpoint)
        now = time.time()
        ttl = max(settings.DEFENSE_RATE_WINDOW * 2, 60)

        try:
            result = await client.eval(
                cls._LEAKY_BUCKET_SCRIPT,
                1,
                key,
                capacity,
                leak_rate,
                now,
                requested,
                ttl,
            )

            allowed = bool(result[0])
            remaining = int(result[1])
            retry_after = int(result[2])
            level = int(result[3])

            if not allowed:
                logger.warning(
                    "leaky_bucket_rate_limited",
                    identifier=identifier,
                    scope=scope,
                    endpoint=endpoint,
                    capacity=capacity,
                    level=level,
                    retry_after=retry_after,
                )

            return {
                "allowed": allowed,
                "remaining": remaining,
                "limit": capacity,
                "retry_after": retry_after,
                "level": level,
                "algorithm": "leaky_bucket",
            }

        except Exception as e:
            logger.error("leaky_bucket_error", error=str(e))
            # Fail-Open
            return {
                "allowed": True,
                "remaining": capacity,
                "limit": capacity,
                "retry_after": 0,
                "level": 0,
                "algorithm": "leaky_bucket",
            }

    # ─── Utilities ─────────────────────────────────────────

    @classmethod
    async def get_status(
        cls,
        identifier: str,
        scope: str = "ip",
        endpoint: str = "",
        capacity: Optional[int] = None,
        leak_rate: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        بترجع حالة الـ bucket من غير ما تستهلك.
        """
        capacity = capacity or settings.DEFENSE_RATE_LIMIT
        default_leak_rate = capacity / settings.DEFENSE_RATE_WINDOW

        client = cls.get_client()
        if not client:
            return {
                "level": 0,
                "capacity": capacity,
                "fill_percentage": 0.0,
            }

        key = cls._build_key(identifier, scope, endpoint)

        try:
            data = await client.hmget(
                key, "level", "last_leak", "leak_rate", "capacity"
            )
            stored_level = float(data[0]) if data[0] else 0.0
            last_leak = float(data[1]) if data[1] else time.time()
            stored_leak_rate = float(data[2]) if data[2] else None
            stored_capacity = int(data[3]) if data[3] else capacity

            effective_leak_rate = (
                leak_rate
                or stored_leak_rate
                or default_leak_rate
            )

            # احسب الـ leak
            now = time.time()
            time_passed = now - last_leak
            if time_passed > 0:
                leaked = time_passed * effective_leak_rate
                level = max(0, stored_level - leaked)
            else:
                level = stored_level

            return {
                "level": int(level),
                "capacity": stored_capacity,
                "fill_percentage": round((level / stored_capacity) * 100, 2) if stored_capacity > 0 else 0.0,
                "leak_rate": effective_leak_rate,
            }
        except Exception as e:
            logger.error("leaky_bucket_status_error", error=str(e))
            return {
                "level": 0,
                "capacity": capacity,
                "fill_percentage": 0.0,
            }

    @classmethod
    async def reset(
        cls,
        identifier: str,
        scope: str = "ip",
        endpoint: str = "",
    ) -> None:
        """بتعيد تعيين الـ bucket (بتملاه)."""
        client = cls.get_client()
        if not client:
            return

        key = cls._build_key(identifier, scope, endpoint)

        try:
            await client.delete(key)
            logger.info(
                "leaky_bucket_reset",
                identifier=identifier,
                scope=scope,
                endpoint=endpoint,
            )
        except Exception as e:
            logger.error("leaky_bucket_reset_error", error=str(e))

    @classmethod
    async def close(cls) -> None:
        """بتقفل Redis."""
        if cls._redis_client:
            await cls._redis_client.close()
            cls._redis_client = None