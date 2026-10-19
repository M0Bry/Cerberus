"""
Cost-Based Rate Limiter — Limits based on endpoint cost.

بيوفر:
- Cost-based limits (كل endpoint له تكلفة)
- Weighted rate limiting (الطلبات الغالية بتكلف أكتر)
- Redis-backed
- Atomic operations
- Per-IP, Per-User, Per-Endpoint

الفكرة:
- كل endpoint له cost
- الـ cost بيتخصم من budget
- Budget يومي/ساعي لكل مستخدم

أمثلة:
- /health: cost = 1 (رخيص)
- /api/v1/users/me: cost = 5
- /api/v1/reports/generate: cost = 100 (غالي)
- /api/v1/ai/analyze: cost = 200 (غالي جداً)

الاستخدام:
- APIs بتوفر خدمات غالية
- حماية من abuse للخدمات الحساسة
- Fair usage policy
"""

import time
from typing import Any, Dict, Optional

import redis.asyncio as redis
import structlog

from app.core.config import settings

logger = structlog.get_logger()


class CostLimiter:
    """
    Cost-Based Rate Limiter.

    الفكرة:
    - كل endpoint له cost محدد
    - الـ cost بيتخصم من budget
    - لو الـ budget خلص → reject
    - الـ budget بيتجدد يومياً/ساعياً

    Endpoints Classification:
    - Free (cost=1):      /health, /docs, /openapi.json
    - Cheap (cost=5):     /users/me, /auth/*
    - Normal (cost=10):   /engagements, /osint
    - Expensive (cost=50): /red-team, /risk-assessment
    - Very Expensive (cost=100): /reports/generate, /ai/analyze
    """

    _redis_client: Optional[redis.Redis] = None

    # ─── Endpoint Costs ────────────────────────────────────
    # كل pattern له cost
    # الترتيب مهم! (الأطول الأول)
    ENDPOINT_COSTS: Dict[str, int] = {
        # Very Expensive (100+)
        "/api/v1/reports/generate": 100,
        "/api/v1/reports/": 50,
        "/api/v1/ai/": 100,
        "/api/v1/red-team/": 75,
        "/api/v1/attack-planning/": 50,
        "/api/v1/risk-assessment/": 50,
        "/api/v1/osint/": 30,

        # Expensive (30-99)
        "/api/v1/engagements": 20,
        "/api/v1/documents": 15,

        # Normal (10-29)
        "/api/v1/users": 5,
        "/api/v1/auth": 5,
        "/api/v1/notifications": 3,
        "/api/v1/dashboard": 5,

        # Cheap (1-9)
        "/api/v1/health": 1,
        "/health": 1,
        "/docs": 1,
        "/redoc": 1,
        "/openapi.json": 1,
        "/favicon.ico": 1,
    }

    # ─── Default Cost ──────────────────────────────────────
    DEFAULT_COST = 10

    # ─── Budget ────────────────────────────────────────────
    # Budget الافتراضي (per user per day)
    DEFAULT_DAILY_BUDGET = 10000  # 10000 cost units/day

    # ─── Lua Script ─────────────────────────────────────────
    _COST_SCRIPT = """
    local key = KEYS[1]
    local budget = tonumber(ARGV[1])
    local cost = tonumber(ARGV[2])
    local now = tonumber(ARGV[3])
    local window = tonumber(ARGV[4])
    local ttl = tonumber(ARGV[5])

    -- 1. جيب الحالة
    local data = redis.call('HMGET', key, 'used', 'window_start')
    local used = tonumber(data[1])
    local window_start = tonumber(data[2])

    -- 2. لو أول مرة أو الـ window انتهت → ابدأ جديد
    if used == nil or window_start == nil or (now - window_start) >= window then
        used = 0
        window_start = now
    end

    -- 3. فحص لو فيه budget كفاية
    local allowed = false
    local remaining = budget - used

    if remaining >= cost then
        used = used + cost
        allowed = true
        remaining = budget - used
    end

    -- 4. احفظ
    redis.call('HMSET', key,
        'used', used,
        'window_start', window_start,
        'budget', budget
    )
    redis.call('EXPIRE', key, ttl)

    -- 5. احسب وقت التجديد
    local reset_after = math.ceil(window - (now - window_start))
    if reset_after < 0 then
        reset_after = 0
    end

    return {allowed and 1 or 0, math.floor(remaining), reset_after, math.floor(used)}
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
                logger.error("cost_limiter_redis_init_failed", error=str(e))
                return None
        return cls._redis_client

    @staticmethod
    def _build_key(identifier: str, scope: str = "user") -> str:
        """بتبني الـ Redis key."""
        return f"cost_limit:{scope}:{identifier}"

    # ─── Cost Calculation ──────────────────────────────────

    @classmethod
    def get_endpoint_cost(cls, path: str) -> int:
        """
        بترجع تكلفة الـ endpoint.

        بيستخدم longest match (الأطول الأول).
        """
        if not path:
            return cls.DEFAULT_COST

        # رتب حسب الطول (تنازلياً) عشان نلاقي الأطول
        sorted_patterns = sorted(
            cls.ENDPOINT_COSTS.keys(),
            key=len,
            reverse=True,
        )

        for pattern in sorted_patterns:
            if path.startswith(pattern):
                return cls.ENDPOINT_COSTS[pattern]

        return cls.DEFAULT_COST

    # ─── Main API ──────────────────────────────────────────

    @classmethod
    async def check(
        cls,
        identifier: str,
        path: str,
        scope: str = "user",
        budget: Optional[int] = None,
        window: int = 86400,  # 24 ساعة
        cost: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        بيفحص لو الطلب مسموح (cost-based).

        Args:
            identifier: user_id أو IP
            path: المسار المطلوب
            scope: user / ip
            budget: الـ budget الكلي (default: 10000)
            window: مدة الـ budget (default: 86400 = يوم)
            cost: التكلفة (لو مش موجودة، بتحدد من path)

        Returns:
            dict فيه:
            - allowed: bool
            - cost: تكلفة الطلب
            - remaining: الـ budget المتبقي
            - total_budget: الـ budget الكلي
            - used: المستهلك
            - reset_after: وقت تجديد الـ budget
            - algorithm: "cost"
        """
        budget = budget or cls.DEFAULT_DAILY_BUDGET
        cost = cost if cost is not None else cls.get_endpoint_cost(path)

        client = cls.get_client()
        if not client:
            # Fail-Open
            return {
                "allowed": True,
                "cost": cost,
                "remaining": budget,
                "total_budget": budget,
                "used": 0,
                "reset_after": window,
                "algorithm": "cost",
            }

        key = cls._build_key(identifier, scope)
        now = time.time()
        ttl = window + 60  # TTL أطول شوية من الـ window

        try:
            result = await client.eval(
                cls._COST_SCRIPT,
                1,
                key,
                budget,
                cost,
                now,
                window,
                ttl,
            )

            allowed = bool(result[0])
            remaining = int(result[1])
            reset_after = int(result[2])
            used = int(result[3])

            if not allowed:
                logger.warning(
                    "cost_limiter_budget_exceeded",
                    identifier=identifier,
                    scope=scope,
                    path=path,
                    cost=cost,
                    budget=budget,
                    used=used,
                )

            return {
                "allowed": allowed,
                "cost": cost,
                "remaining": remaining,
                "total_budget": budget,
                "used": used,
                "reset_after": reset_after,
                "algorithm": "cost",
            }

        except Exception as e:
            logger.error("cost_limiter_error", error=str(e))
            # Fail-Open
            return {
                "allowed": True,
                "cost": cost,
                "remaining": budget,
                "total_budget": budget,
                "used": 0,
                "reset_after": window,
                "algorithm": "cost",
            }

    # ─── Admin API ─────────────────────────────────────────

    @classmethod
    def set_endpoint_cost(cls, path: str, cost: int) -> None:
        """بيحدد تكلفة endpoint."""
        if cost < 0:
            raise ValueError("Cost must be >= 0")
        cls.ENDPOINT_COSTS[path] = cost
        logger.info("cost_limiter_endpoint_cost_set", path=path, cost=cost)

    @classmethod
    def remove_endpoint_cost(cls, path: str) -> None:
        """بيشيل تكلفة endpoint (يرجع للـ default)."""
        cls.ENDPOINT_COSTS.pop(path, None)

    @classmethod
    def get_all_costs(cls) -> Dict[str, int]:
        """بترجع كل التكاليف."""
        return dict(cls.ENDPOINT_COSTS)

    # ─── Utilities ─────────────────────────────────────────

    @classmethod
    async def get_status(
        cls,
        identifier: str,
        scope: str = "user",
        budget: Optional[int] = None,
        window: int = 86400,
    ) -> Dict[str, Any]:
        """بترجع حالة الـ budget."""
        budget = budget or cls.DEFAULT_DAILY_BUDGET

        client = cls.get_client()
        if not client:
            return {
                "used": 0,
                "budget": budget,
                "remaining": budget,
                "used_percentage": 0.0,
            }

        key = cls._build_key(identifier, scope)

        try:
            data = await client.hmget(key, "used", "window_start")
            stored_used = float(data[0]) if data[0] else 0.0
            window_start = float(data[1]) if data[1] else time.time()

            # لو الـ window انتهت → الـ budget اتجدد
            now = time.time()
            if (now - window_start) >= window:
                stored_used = 0.0

            remaining = max(0, budget - stored_used)

            return {
                "used": int(stored_used),
                "budget": budget,
                "remaining": int(remaining),
                "used_percentage": round((stored_used / budget) * 100, 2) if budget > 0 else 0.0,
                "window_start": window_start,
                "reset_after": max(0, int(window - (now - window_start))),
            }
        except Exception as e:
            logger.error("cost_limiter_status_error", error=str(e))
            return {
                "used": 0,
                "budget": budget,
                "remaining": budget,
                "used_percentage": 0.0,
            }

    @classmethod
    async def reset(
        cls,
        identifier: str,
        scope: str = "user",
    ) -> None:
        """بتعيد تعيين الـ budget."""
        client = cls.get_client()
        if not client:
            return

        key = cls._build_key(identifier, scope)

        try:
            await client.delete(key)
            logger.info(
                "cost_limiter_reset",
                identifier=identifier,
                scope=scope,
            )
        except Exception as e:
            logger.error("cost_limiter_reset_error", error=str(e))

    @classmethod
    async def close(cls) -> None:
        """بتقفل Redis."""
        if cls._redis_client:
            await cls._redis_client.close()
            cls._redis_client = None