"""
Adaptive Rate Limiter — Limits change based on behavior.

بيوفر:
- Adaptive limits (بتتغير حسب السلوك)
- Multi-tier limits (عادي / مشبوه / خطير)
- Integration مع AbuseDetector + AnomalyDetector
- Redis-backed
- Atomic operations

الفكرة:
- المستخدم العادي → حد عالي
- المستخدم المشبوه → حد متوسط
- المستخدم الخطير → حد منخفض

الاستخدام:
- APIs بتحتاج حماية متدرجة
- حماية الخدمات الحساسة
- منع الـ insider threats
"""

import time
from typing import Any, Dict, Optional

import redis.asyncio as redis
import structlog

from app.core.config import settings

logger = structlog.get_logger()


class AdaptiveLimiter:
    """
    Adaptive Rate Limiter.

    الفكرة:
    - 3 مستويات من الحدود
    - كل مستوى له multiplier
    - الـ multiplier بيتحدد حسب السلوك

    المستويات:
    - normal:   multiplier = 1.0  (100%)
    - suspicious: multiplier = 0.5  (50%)
    - dangerous: multiplier = 0.1  (10%)
    """

    _redis_client: Optional[redis.Redis] = None

    # ─── Tier Definitions ──────────────────────────────────
    TIERS = {
        "trusted": {
            "multiplier": 2.0,      # 200% (ضعف الحد)
            "description": "موثوق - بياخد ضعف الحد",
        },
        "normal": {
            "multiplier": 1.0,      # 100% (الحد الطبيعي)
            "description": "عادي - الحد الطبيعي",
        },
        "suspicious": {
            "multiplier": 0.5,      # 50% (نص الحد)
            "description": "مشبوه - نص الحد",
        },
        "dangerous": {
            "multiplier": 0.1,      # 10% (عُشر الحد)
            "description": "خطير - عُشر الحد",
        },
        "blocked": {
            "multiplier": 0.0,      # 0% (محظور)
            "description": "محظور - صفر",
        },
    }

    # ─── Lua Script ─────────────────────────────────────────
    _ADAPTIVE_SCRIPT = """
    local key = KEYS[1]
    local capacity = tonumber(ARGV[1])
    local refill_rate = tonumber(ARGV[2])
    local now = tonumber(ARGV[3])
    local requested = tonumber(ARGV[4])
    local ttl = tonumber(ARGV[5])

    -- 1. جيب الحالة
    local data = redis.call('HMGET', key, 'tokens', 'last_refill')
    local tokens = tonumber(data[1])
    local last_refill = tonumber(data[2])

    -- 2. أول مرة
    if tokens == nil then
        tokens = capacity
        last_refill = now
    end

    -- 3. احسب الـ refill
    local time_passed = now - last_refill
    if time_passed > 0 then
        local refill = time_passed * refill_rate
        tokens = math.min(capacity, tokens + refill)
        last_refill = now
    end

    -- 4. فحص
    local allowed = false
    local remaining = tokens

    if tokens >= requested then
        tokens = tokens - requested
        allowed = true
        remaining = tokens
    end

    -- 5. احفظ
    redis.call('HMSET', key,
        'tokens', tokens,
        'last_refill', last_refill,
        'refill_rate', refill_rate,
        'capacity', capacity
    )
    redis.call('EXPIRE', key, ttl)

    -- 6. retry_after
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
                logger.error("adaptive_limiter_redis_init_failed", error=str(e))
                return None
        return cls._redis_client

    @staticmethod
    def _build_key(identifier: str, scope: str = "ip", endpoint: str = "") -> str:
        """بتبني الـ Redis key."""
        parts = ["adaptive_limit", scope, identifier]
        if endpoint:
            parts.append(endpoint)
        return ":".join(parts)

    # ─── Tier Management ───────────────────────────────────

    @classmethod
    def get_tier_multiplier(cls, tier: str) -> float:
        """بترجع الـ multiplier لمستوى معين."""
        return cls.TIERS.get(tier, cls.TIERS["normal"])["multiplier"]

    @classmethod
    async def set_tier(
        cls,
        identifier: str,
        tier: str,
        scope: str = "ip",
        ttl: int = 3600,
    ) -> None:
        """
        بتحدد المستوى لـ identifier.

        Args:
            identifier: IP أو user_id
            tier: trusted / normal / suspicious / dangerous / blocked
            scope: ip / user
            ttl: مدة المستوى (ثواني)
        """
        if tier not in cls.TIERS:
            logger.warning("adaptive_limiter_invalid_tier", tier=tier)
            return

        client = cls.get_client()
        if not client:
            return

        key = f"adaptive_tier:{scope}:{identifier}"

        try:
            await client.setex(key, ttl, tier)
            logger.info(
                "adaptive_limiter_tier_set",
                identifier=identifier,
                tier=tier,
                scope=scope,
                ttl=ttl,
            )
        except Exception as e:
            logger.error("adaptive_limiter_set_tier_error", error=str(e))

    @classmethod
    async def get_tier(
        cls,
        identifier: str,
        scope: str = "ip",
    ) -> str:
        """بترجع المستوى الحالي لـ identifier."""
        client = cls.get_client()
        if not client:
            return "normal"

        key = f"adaptive_tier:{scope}:{identifier}"

        try:
            tier = await client.get(key)
            if tier and tier in cls.TIERS:
                return tier
            return "normal"
        except Exception as e:
            logger.error("adaptive_limiter_get_tier_error", error=str(e))
            return "normal"

    @classmethod
    async def clear_tier(
        cls,
        identifier: str,
        scope: str = "ip",
    ) -> None:
        """بتمسح المستوى المخصص (يرجع لـ normal)."""
        client = cls.get_client()
        if not client:
            return

        key = f"adaptive_tier:{scope}:{identifier}"

        try:
            await client.delete(key)
            logger.info(
                "adaptive_limiter_tier_cleared",
                identifier=identifier,
                scope=scope,
            )
        except Exception as e:
            logger.error("adaptive_limiter_clear_tier_error", error=str(e))

    # ─── Main API ──────────────────────────────────────────

    @classmethod
    async def check(
        cls,
        identifier: str,
        base_capacity: Optional[int] = None,
        scope: str = "ip",
        endpoint: str = "",
        requested: int = 1,
    ) -> Dict[str, Any]:
        """
        بيفحص لو الطلب مسموح (مع adaptive limits).

        Args:
            identifier: IP أو user_id
            base_capacity: الحد الأساسي (default: DEFENSE_RATE_LIMIT)
            scope: ip / user / endpoint
            endpoint: المسار
            requested: عدد الطلبات

        Returns:
            dict فيه:
            - allowed: bool
            - remaining: التوكنز المتبقية
            - limit: الحد الفعلي
            - base_limit: الحد الأساسي
            - tier: المستوى الحالي
            - multiplier: معامل المستوى
            - retry_after: ثواني للانتظار
        """
        base_capacity = base_capacity or settings.DEFENSE_RATE_LIMIT

        # 1. جيب المستوى
        tier = await cls.get_tier(identifier, scope)
        multiplier = cls.get_tier_multiplier(tier)

        # 2. احسب الحد الفعلي
        effective_capacity = max(1, int(base_capacity * multiplier))

        # 3. لو المستوى blocked → ارفض فوراً
        if tier == "blocked":
            logger.warning(
                "adaptive_limiter_blocked",
                identifier=identifier,
                scope=scope,
            )
            return {
                "allowed": False,
                "remaining": 0,
                "limit": 0,
                "base_limit": base_capacity,
                "tier": tier,
                "multiplier": multiplier,
                "retry_after": 3600,
                "algorithm": "adaptive",
            }

        # 4. احسب refill rate
        refill_rate = effective_capacity / settings.DEFENSE_RATE_WINDOW

        client = cls.get_client()
        if not client:
            # Fail-Open
            return {
                "allowed": True,
                "remaining": effective_capacity,
                "limit": effective_capacity,
                "base_limit": base_capacity,
                "tier": tier,
                "multiplier": multiplier,
                "retry_after": 0,
                "algorithm": "adaptive",
            }

        key = cls._build_key(identifier, scope, endpoint)
        now = time.time()
        ttl = max(settings.DEFENSE_RATE_WINDOW * 2, 60)

        try:
            result = await client.eval(
                cls._ADAPTIVE_SCRIPT,
                1,
                key,
                effective_capacity,
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
                    "adaptive_limiter_rate_limited",
                    identifier=identifier,
                    scope=scope,
                    tier=tier,
                    limit=effective_capacity,
                    retry_after=retry_after,
                )

            return {
                "allowed": allowed,
                "remaining": remaining,
                "limit": effective_capacity,
                "base_limit": base_capacity,
                "tier": tier,
                "multiplier": multiplier,
                "retry_after": retry_after,
                "algorithm": "adaptive",
            }

        except Exception as e:
            logger.error("adaptive_limiter_error", error=str(e))
            # Fail-Open
            return {
                "allowed": True,
                "remaining": effective_capacity,
                "limit": effective_capacity,
                "base_limit": base_capacity,
                "tier": tier,
                "multiplier": multiplier,
                "retry_after": 0,
                "algorithm": "adaptive",
            }

    # ─── Auto-Detection ────────────────────────────────────

    @classmethod
    async def auto_detect_tier(
        cls,
        identifier: str,
        scope: str = "ip",
    ) -> str:
        """
        بيكتشف المستوى تلقائياً حسب السلوك.

        بيعتمد على:
        - AbuseDetector (للـ abuse history)
        - عدد المحاولات الفاشلة
        - السلوك الشاذ

        Returns:
            tier name
        """
        from app.core.abuse_detector import AbuseDetector

        try:
            # 1. فحص لو محظور
            if scope == "ip":
                is_blocked = await AbuseDetector.is_blocked(identifier)
                if is_blocked:
                    await cls.set_tier(identifier, "blocked", scope, ttl=3600)
                    return "blocked"

            # 2. فحص لو مسيء
            if scope == "ip":
                is_abusive = await AbuseDetector.is_abusive(identifier)
                if is_abusive:
                    await cls.set_tier(identifier, "dangerous", scope, ttl=1800)
                    return "dangerous"

            # 3. الافتراضي
            return "normal"

        except Exception as e:
            logger.error("adaptive_limiter_auto_detect_error", error=str(e))
            return "normal"

    # ─── Utilities ─────────────────────────────────────────

    @classmethod
    async def get_status(
        cls,
        identifier: str,
        scope: str = "ip",
        endpoint: str = "",
        base_capacity: Optional[int] = None,
    ) -> Dict[str, Any]:
        """بترجع حالة الـ limiter."""
        base_capacity = base_capacity or settings.DEFENSE_RATE_LIMIT
        tier = await cls.get_tier(identifier, scope)
        multiplier = cls.get_tier_multiplier(tier)
        effective_capacity = max(1, int(base_capacity * multiplier))

        client = cls.get_client()
        if not client:
            return {
                "tier": tier,
                "multiplier": multiplier,
                "limit": effective_capacity,
                "base_limit": base_capacity,
                "tokens": effective_capacity,
                "fill_percentage": 100.0,
            }

        key = cls._build_key(identifier, scope, endpoint)

        try:
            data = await client.hmget(
                key, "tokens", "last_refill", "refill_rate", "capacity"
            )
            stored_tokens = float(data[0]) if data[0] else effective_capacity
            last_refill = float(data[1]) if data[1] else time.time()
            stored_refill_rate = float(data[2]) if data[2] else None
            stored_capacity = int(data[3]) if data[3] else effective_capacity

            refill_rate = (
                stored_refill_rate
                or (effective_capacity / settings.DEFENSE_RATE_WINDOW)
            )

            now = time.time()
            time_passed = now - last_refill
            if time_passed > 0:
                refill = time_passed * refill_rate
                tokens = min(stored_capacity, stored_tokens + refill)
            else:
                tokens = stored_tokens

            return {
                "tier": tier,
                "multiplier": multiplier,
                "limit": effective_capacity,
                "base_limit": base_capacity,
                "tokens": int(tokens),
                "fill_percentage": round(
                    (tokens / stored_capacity) * 100, 2
                ) if stored_capacity > 0 else 0.0,
            }
        except Exception as e:
            logger.error("adaptive_limiter_status_error", error=str(e))
            return {
                "tier": tier,
                "multiplier": multiplier,
                "limit": effective_capacity,
                "base_limit": base_capacity,
                "tokens": effective_capacity,
                "fill_percentage": 100.0,
            }

    @classmethod
    async def reset(
        cls,
        identifier: str,
        scope: str = "ip",
        endpoint: str = "",
    ) -> None:
        """بتعيد تعيين الـ limiter."""
        client = cls.get_client()
        if not client:
            return

        key = cls._build_key(identifier, scope, endpoint)

        try:
            await client.delete(key)
            logger.info(
                "adaptive_limiter_reset",
                identifier=identifier,
                scope=scope,
            )
        except Exception as e:
            logger.error("adaptive_limiter_reset_error", error=str(e))

    @classmethod
    async def close(cls) -> None:
        """بتقفل Redis."""
        if cls._redis_client:
            await cls._redis_client.close()
            cls._redis_client = None