"""
Token Bucket Rate Limiter — Redis-backed.

بيوفر:
- Token Bucket algorithm
- Burst allowance (مهم للـ API clients)
- Distributed (Redis-backed)
- Atomic operations (Lua Script)
- Per-IP, Per-User, Per-Endpoint

الفرق بينه وبين Sliding Window:
- Sliding Window: بيمنع أي burst
- Token Bucket: بيسمح بـ burst محدود

مثال:
- Sliding Window 100/60s: 100 request موزعين
- Token Bucket: 100 توكن، لو استهلكتهم كلهم في ثانية، يرفض
                    لحد ما يتجددوا
"""

import time
from typing import Any, Dict, Optional

import redis.asyncio as redis
import structlog

from app.core.config import settings

logger = structlog.get_logger()


class TokenBucket:
    """
    Token Bucket Rate Limiter.

    الفكرة:
    - Bucket له capacity (أقصى عدد توكنز)
    - Refill rate (معدل إضافة التوكنز)
    - كل request بتاخد توكن
    - لو مفيش توكنز → reject

    الـ Lua Script بيعمل كل ده atomically:
    1. احسب التوكنز الجديدة من آخر مرة
    2. لو التوكنز < المطلوب → reject
    3. لو التوكنز >= المطلوب → اطرح و allow
    """

    _redis_client: Optional[redis.Redis] = None

    # ─── Lua Script ─────────────────────────────────────────
    # مهم: Lua Script بينفذ atomic في Redis
    # فمفيش race conditions
    #
    # بيحفظ 3 حقول:
    # - tokens: عدد التوكنز الحالي
    # - last_refill: آخر مرة اتحدث
    # - refill_rate: معدل التجديد (عشان get_status)
    _TOKEN_BUCKET_SCRIPT = """
    local key = KEYS[1]
    local capacity = tonumber(ARGV[1])
    local refill_rate = tonumber(ARGV[2])
    local now = tonumber(ARGV[3])
    local requested = tonumber(ARGV[4])
    local ttl = tonumber(ARGV[5])

    -- 1. جيب الحالة الحالية
    local data = redis.call('HMGET', key, 'tokens', 'last_refill')
    local tokens = tonumber(data[1])
    local last_refill = tonumber(data[2])

    -- 2. لو أول مرة → ابدأ ممتلئ
    if tokens == nil then
        tokens = capacity
        last_refill = now
    end

    -- 3. احسب التوكنز الجديدة
    local time_passed = now - last_refill
    if time_passed > 0 then
        local refill = time_passed * refill_rate
        tokens = math.min(capacity, tokens + refill)
        last_refill = now
    end

    -- 4. فحص لو فيه توكنز كفاية
    local allowed = false
    local remaining = tokens

    if tokens >= requested then
        tokens = tokens - requested
        allowed = true
        remaining = tokens
    end

    -- 5. احفظ الحالة (مع refill_rate عشان get_status يستخدمه)
    redis.call('HMSET', key,
        'tokens', tokens,
        'last_refill', last_refill,
        'refill_rate', refill_rate
    )
    redis.call('EXPIRE', key, ttl)

    -- 6. احسب retry_after
    local retry_after = 0
    if not allowed then
        local needed = requested - tokens
        retry_after = math.ceil(needed / refill_rate)
    end

    return {allowed and 1 or 0, math.floor(remaining), retry_after}
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
                logger.error("token_bucket_redis_init_failed", error=str(e))
                return None
        return cls._redis_client

    @staticmethod
    def _build_key(identifier: str, scope: str = "ip", endpoint: str = "") -> str:
        """بتبني الـ Redis key."""
        parts = ["token_bucket", scope, identifier]
        if endpoint:
            parts.append(endpoint)
        return ":".join(parts)

    # ─── Main API ──────────────────────────────────────────

    @classmethod
    async def check(
        cls,
        identifier: str,
        capacity: Optional[int] = None,
        refill_rate: Optional[float] = None,
        scope: str = "ip",
        endpoint: str = "",
        requested: int = 1,
    ) -> Dict[str, Any]:
        """
        بيفحص لو الطلب مسموح.

        Args:
            identifier: IP أو user_id
            capacity: أقصى عدد توكنز (default: DEFENSE_RATE_LIMIT)
            refill_rate: معدل التجديد (توكن/ثانية)
            scope: "ip" / "user" / "endpoint"
            endpoint: المسار (اختياري)
            requested: عدد التوكنز المطلوبة (default: 1)

        Returns:
            dict فيه:
            - allowed: bool
            - remaining: عدد التوكنز المتبقية
            - limit: capacity
            - retry_after: ثواني للانتظار
            - algorithm: "token_bucket"
        """
        capacity = capacity or settings.DEFENSE_RATE_LIMIT
        refill_rate = refill_rate or (capacity / settings.DEFENSE_RATE_WINDOW)

        client = cls.get_client()
        if not client:
            # Fail-Open
            return {
                "allowed": True,
                "remaining": capacity,
                "limit": capacity,
                "retry_after": 0,
                "algorithm": "token_bucket",
            }

        key = cls._build_key(identifier, scope, endpoint)
        now = time.time()
        ttl = max(settings.DEFENSE_RATE_WINDOW * 2, 60)

        try:
            result = await client.eval(
                cls._TOKEN_BUCKET_SCRIPT,
                1,
                key,
                capacity,
                refill_rate,
                now,
                requested,
                ttl,
            )

            allowed = bool(result[0])
            remaining = int(result[1])
            retry_after = int(result[2])

            if not allowed:
                logger.warning(
                    "token_bucket_rate_limited",
                    identifier=identifier,
                    scope=scope,
                    endpoint=endpoint,
                    capacity=capacity,
                    retry_after=retry_after,
                )

            return {
                "allowed": allowed,
                "remaining": remaining,
                "limit": capacity,
                "retry_after": retry_after,
                "algorithm": "token_bucket",
            }

        except Exception as e:
            logger.error("token_bucket_error", error=str(e))
            # Fail-Open
            return {
                "allowed": True,
                "remaining": capacity,
                "limit": capacity,
                "retry_after": 0,
                "algorithm": "token_bucket",
            }

    # ─── Utilities ─────────────────────────────────────────

    @classmethod
    async def get_status(
        cls,
        identifier: str,
        scope: str = "ip",
        endpoint: str = "",
        capacity: Optional[int] = None,
        refill_rate: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        بترجع حالة الـ bucket من غير ما تستهلك.

        بتستخدم refill_rate المخزن في Redis (لو موجود)،
        وإلا بتستخدم اللي مبعوت، وإلا الافتراضي.

        ده مهم عشان نتأكد إن الحساب صح حتى لو الـ caller
        مش عارف الـ refill_rate الأصلي.
        """
        capacity = capacity or settings.DEFENSE_RATE_LIMIT
        default_refill_rate = capacity / settings.DEFENSE_RATE_WINDOW

        client = cls.get_client()
        if not client:
            return {
                "tokens": capacity,
                "capacity": capacity,
                "fill_percentage": 100.0,
            }

        key = cls._build_key(identifier, scope, endpoint)

        try:
            # نقرا refill_rate المخزن كمان
            data = await client.hmget(key, "tokens", "last_refill", "refill_rate")
            stored_tokens = float(data[0]) if data[0] else capacity
            last_refill = float(data[1]) if data[1] else time.time()
            stored_refill_rate = float(data[2]) if data[2] else None

            # الأولوية: parameter > stored > default
            effective_refill_rate = (
                refill_rate
                or stored_refill_rate
                or default_refill_rate
            )

            # احسب الـ refill
            now = time.time()
            time_passed = now - last_refill
            if time_passed > 0:
                refill = time_passed * effective_refill_rate
                tokens = min(capacity, stored_tokens + refill)
            else:
                tokens = stored_tokens

            return {
                "tokens": int(tokens),
                "capacity": capacity,
                "fill_percentage": round((tokens / capacity) * 100, 2),
                "refill_rate": effective_refill_rate,
            }
        except Exception as e:
            logger.error("token_bucket_status_error", error=str(e))
            return {
                "tokens": capacity,
                "capacity": capacity,
                "fill_percentage": 100.0,
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
                "token_bucket_reset",
                identifier=identifier,
                scope=scope,
                endpoint=endpoint,
            )
        except Exception as e:
            logger.error("token_bucket_reset_error", error=str(e))

    @classmethod
    async def close(cls) -> None:
        """بتقفل Redis."""
        if cls._redis_client:
            await cls._redis_client.close()
            cls._redis_client = None