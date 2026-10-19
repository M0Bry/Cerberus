"""
Geo Rate Limiter — Limits based on geographic location.

بيوفر:
- Country-based limits
- Trusted / Normal / Restricted / Blocked countries
- Integration مع GeoIP
- Redis-backed
- Atomic operations

الفكرة:
- كل دولة ليها tier
- كل tier له multiplier
- الدولة بتتحدد من IP

Tiers:
- trusted:    ضعف الحد (US, EU, ...)
- normal:     الحد الطبيعي
- restricted: نص الحد (دول فيها هجمات)
- blocked:    ممنوع تماماً (KP, IR, SY)

الاستخدام:
- حماية من هجمات إقليمية
- Compliance (GDPR, etc.)
- تقليل الضغط من مناطق معينة
"""

import time
from typing import Any, Dict, Optional

import redis.asyncio as redis
import structlog

from app.core.config import settings

logger = structlog.get_logger()


class GeoLimiter:
    """
    Geo Rate Limiter.

    الفكرة:
    - كل دولة لها tier
    - الـ tier بيحدد الـ multiplier
    - الدولة بتتحدد من IP (GeoIP)
    """

    _redis_client: Optional[redis.Redis] = None

    # ─── Country Tiers ─────────────────────────────────────
    # كل دولة لها tier
    COUNTRY_TIERS: Dict[str, str] = {
        # ─── Trusted (2x) ───
        "US": "trusted",
        "CA": "trusted",
        "GB": "trusted",
        "DE": "trusted",
        "FR": "trusted",
        "NL": "trusted",
        "SE": "trusted",
        "NO": "trusted",
        "DK": "trusted",
        "FI": "trusted",
        "CH": "trusted",
        "AT": "trusted",
        "BE": "trusted",
        "IE": "trusted",
        "AU": "trusted",
        "NZ": "trusted",
        "JP": "trusted",
        "SG": "trusted",
        "KR": "trusted",
        "AE": "trusted",
        "EG": "trusted",
        "SA": "trusted",

        # ─── Restricted (0.5x) ───
        "CN": "restricted",
        "RU": "restricted",
        "VN": "restricted",
        "ID": "restricted",
        "PH": "restricted",
        "NG": "restricted",
        "PK": "restricted",
        "BD": "restricted",
        "UA": "restricted",
        "TR": "restricted",

        # ─── Blocked (0x) ───
        "KP": "blocked",   # North Korea
        "IR": "blocked",   # Iran
        "SY": "blocked",   # Syria
        "CU": "blocked",   # Cuba
    }

    # ─── Tier Multipliers ──────────────────────────────────
    TIER_MULTIPLIERS: Dict[str, float] = {
        "trusted": 2.0,
        "normal": 1.0,
        "restricted": 0.5,
        "blocked": 0.0,
    }

    # ─── Lua Script ─────────────────────────────────────────
    _GEO_SCRIPT = """
    local key = KEYS[1]
    local capacity = tonumber(ARGV[1])
    local refill_rate = tonumber(ARGV[2])
    local now = tonumber(ARGV[3])
    local requested = tonumber(ARGV[4])
    local ttl = tonumber(ARGV[5])

    local data = redis.call('HMGET', key, 'tokens', 'last_refill')
    local tokens = tonumber(data[1])
    local last_refill = tonumber(data[2])

    if tokens == nil then
        tokens = capacity
        last_refill = now
    end

    local time_passed = now - last_refill
    if time_passed > 0 then
        local refill = time_passed * refill_rate
        tokens = math.min(capacity, tokens + refill)
        last_refill = now
    end

    local allowed = false
    local remaining = tokens

    if tokens >= requested then
        tokens = tokens - requested
        allowed = true
        remaining = tokens
    end

    redis.call('HMSET', key,
        'tokens', tokens,
        'last_refill', last_refill,
        'refill_rate', refill_rate,
        'capacity', capacity
    )
    redis.call('EXPIRE', key, ttl)

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
                logger.error("geo_limiter_redis_init_failed", error=str(e))
                return None
        return cls._redis_client

    @staticmethod
    def _build_key(identifier: str, endpoint: str = "") -> str:
        """بتبني الـ Redis key."""
        parts = ["geo_limit", identifier]
        if endpoint:
            parts.append(endpoint)
        return ":".join(parts)

    # ─── Country Helpers ───────────────────────────────────

    @classmethod
    def get_country_tier(cls, country_code: str) -> str:
        """بترجع الـ tier لدولة معينة."""
        if not country_code:
            return "normal"
        return cls.COUNTRY_TIERS.get(country_code.upper(), "normal")

    @classmethod
    def get_tier_multiplier(cls, tier: str) -> float:
        """بترجع الـ multiplier."""
        return cls.TIER_MULTIPLIERS.get(tier, 1.0)

    @classmethod
    def is_country_blocked(cls, country_code: str) -> bool:
        """بيفحص لو الدولة محظورة."""
        return cls.get_country_tier(country_code) == "blocked"

    # ─── GeoIP Helpers ─────────────────────────────────────

    @classmethod
    async def get_country_from_ip(cls, ip: str) -> Optional[str]:
        """
        بترجع كود الدولة من IP.

        بيستخدم app.utils.geoip لو موجود.
        """
        try:
            from app.utils.geoip import get_geo_info
            geo = get_geo_info(ip)
            if geo and geo.get("country"):
                return geo["country"].upper()
        except ImportError:
            pass
        except Exception as e:
            logger.warning("geo_limiter_geoip_error", error=str(e))

        # Fallback: localhost
        if ip in ("127.0.0.1", "::1", "localhost", "unknown"):
            return "US"  # نعتبر localhost كـ US (تطوير)

        return None

    # ─── Main API ──────────────────────────────────────────

    @classmethod
    async def check(
        cls,
        identifier: str,
        country_code: Optional[str] = None,
        base_capacity: Optional[int] = None,
        endpoint: str = "",
        requested: int = 1,
    ) -> Dict[str, Any]:
        """
        بيفحص لو الطلب مسموح (geo-based).

        Args:
            identifier: IP
            country_code: كود الدولة (لو مش موجود، بيحدد من IP)
            base_capacity: الحد الأساسي
            endpoint: المسار
            requested: عدد الطلبات

        Returns:
            dict فيه:
            - allowed: bool
            - remaining: التوكنز المتبقية
            - limit: الحد الفعلي
            - base_limit: الحد الأساسي
            - country: كود الدولة
            - tier: المستوى
            - multiplier: معامل
            - retry_after
        """
        base_capacity = base_capacity or settings.DEFENSE_RATE_LIMIT

        # 1. حدد الدولة
        if not country_code:
            country_code = await cls.get_country_from_ip(identifier)

        country_code = (country_code or "unknown").upper()

        # 2. حدد الـ tier
        tier = cls.get_country_tier(country_code)
        multiplier = cls.get_tier_multiplier(tier)

        # 3. لو blocked → ارفض فوراً
        if tier == "blocked":
            logger.warning(
                "geo_limiter_blocked_country",
                identifier=identifier,
                country=country_code,
            )
            return {
                "allowed": False,
                "remaining": 0,
                "limit": 0,
                "base_limit": base_capacity,
                "country": country_code,
                "tier": tier,
                "multiplier": multiplier,
                "retry_after": 86400,  # 24 ساعة
                "algorithm": "geo",
            }

        # 4. احسب الحد الفعلي
        effective_capacity = max(1, int(base_capacity * multiplier))
        refill_rate = effective_capacity / settings.DEFENSE_RATE_WINDOW

        client = cls.get_client()
        if not client:
            return {
                "allowed": True,
                "remaining": effective_capacity,
                "limit": effective_capacity,
                "base_limit": base_capacity,
                "country": country_code,
                "tier": tier,
                "multiplier": multiplier,
                "retry_after": 0,
                "algorithm": "geo",
            }

        key = cls._build_key(identifier, endpoint)
        now = time.time()
        ttl = max(settings.DEFENSE_RATE_WINDOW * 2, 60)

        try:
            result = await client.eval(
                cls._GEO_SCRIPT,
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
                    "geo_limiter_rate_limited",
                    identifier=identifier,
                    country=country_code,
                    tier=tier,
                    limit=effective_capacity,
                    retry_after=retry_after,
                )

            return {
                "allowed": allowed,
                "remaining": remaining,
                "limit": effective_capacity,
                "base_limit": base_capacity,
                "country": country_code,
                "tier": tier,
                "multiplier": multiplier,
                "retry_after": retry_after,
                "algorithm": "geo",
            }

        except Exception as e:
            logger.error("geo_limiter_error", error=str(e))
            return {
                "allowed": True,
                "remaining": effective_capacity,
                "limit": effective_capacity,
                "base_limit": base_capacity,
                "country": country_code,
                "tier": tier,
                "multiplier": multiplier,
                "retry_after": 0,
                "algorithm": "geo",
            }

    # ─── Admin API ─────────────────────────────────────────

    @classmethod
    def add_country(
        cls,
        country_code: str,
        tier: str,
    ) -> None:
        """بيضيف دولة للـ tier map."""
        if tier not in cls.TIER_MULTIPLIERS:
            raise ValueError(f"Invalid tier: {tier}")
        cls.COUNTRY_TIERS[country_code.upper()] = tier

    @classmethod
    def remove_country(cls, country_code: str) -> None:
        """بيشيل دولة (ترجع normal)."""
        cls.COUNTRY_TIERS.pop(country_code.upper(), None)

    @classmethod
    def get_all_countries(cls) -> Dict[str, str]:
        """بترجع كل الدول وتصنيفاتها."""
        return dict(cls.COUNTRY_TIERS)

    @classmethod
    def get_countries_by_tier(cls, tier: str) -> list:
        """بترجع كل الدول في tier معين."""
        return [
            country
            for country, t in cls.COUNTRY_TIERS.items()
            if t == tier
        ]

    # ─── Utilities ─────────────────────────────────────────

    @classmethod
    async def get_status(
        cls,
        identifier: str,
        country_code: Optional[str] = None,
        endpoint: str = "",
        base_capacity: Optional[int] = None,
    ) -> Dict[str, Any]:
        """بترجع الحالة."""
        base_capacity = base_capacity or settings.DEFENSE_RATE_LIMIT

        if not country_code:
            country_code = await cls.get_country_from_ip(identifier)

        country_code = (country_code or "unknown").upper()
        tier = cls.get_country_tier(country_code)
        multiplier = cls.get_tier_multiplier(tier)
        effective_capacity = max(1, int(base_capacity * multiplier))

        client = cls.get_client()
        if not client:
            return {
                "country": country_code,
                "tier": tier,
                "multiplier": multiplier,
                "limit": effective_capacity,
                "base_limit": base_capacity,
                "tokens": effective_capacity,
                "fill_percentage": 100.0,
            }

        key = cls._build_key(identifier, endpoint)

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
                "country": country_code,
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
            logger.error("geo_limiter_status_error", error=str(e))
            return {
                "country": country_code,
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
        endpoint: str = "",
    ) -> None:
        """بتعيد تعيين الحد."""
        client = cls.get_client()
        if not client:
            return

        key = cls._build_key(identifier, endpoint)

        try:
            await client.delete(key)
            logger.info("geo_limiter_reset", identifier=identifier)
        except Exception as e:
            logger.error("geo_limiter_reset_error", error=str(e))

    @classmethod
    async def close(cls) -> None:
        """بتقفل Redis."""
        if cls._redis_client:
            await cls._redis_client.close()
            cls._redis_client = None