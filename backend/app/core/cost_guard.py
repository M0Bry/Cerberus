"""
Cost-aware limiter (Tier 1, Part C).

Endpoints that SEND EMAIL or CREATE ACCOUNTS have a real cost per call
(OTP mails, account rows, admin-inbox entries). The generic per-IP
request buckets do not price that cost: an attacker who rotates
emails (or emails from a botnet of IPs) can still burn mail-sending
budget without ever tripping a request-rate rule.

CostGuard charges EXPENSIVE operations against per-identifier sliding
windows — e.g. "resend-otp: 3/hour per EMAIL and 10/hour per IP".

Design notes:
* Class-level in-memory store: service objects are instantiated PER
  REQUEST, so instance state would not accumulate. The store is
  process-shared, exactly like AbuseDetector's.
* Redis-first with in-memory fallback (same pattern as the rest of
  the defense stack): with Redis down the in-memory store is
  authoritative and the limiter is never silently disabled.
* Windows are trimmed lazily — no background task, no growth.
"""

from __future__ import annotations

import time
from typing import Dict, List, Tuple

import structlog

from app.core.config import settings

logger = structlog.get_logger()


class CostGuard:
    """Sliding-window budget for expensive operations."""

    # key -> [unix timestamps]
    _events: Dict[str, List[float]] = {}
    # key -> monotonic increment (tie-breaker for identical timestamps)
    _seq: int = 0

    _redis_client = None
    _redis_failed = False

    # ─── Redis (optional) ───────────────────────────────────

    @classmethod
    async def _get_redis(cls):
        if cls._redis_failed:
            return None
        if cls._redis_client is not None:
            return cls._redis_client
        try:
            import redis.asyncio as aioredis

            from app.core.config import settings as _s

            client = aioredis.from_url(
                _s.REDIS_URL, encoding="utf-8", decode_responses=True
            )
            await client.ping()
            cls._redis_client = client
            return client
        except Exception:
            cls._redis_failed = True
            return None

    @staticmethod
    def _key(operation: str, identifier: str) -> str:
        return f"cost:{operation}:{identifier.strip().lower()}"

    # ─── Core ───────────────────────────────────────────────

    @classmethod
    def _memory_count(cls, key: str, window: int) -> int:
        now = time.time()
        events = cls._events.get(key)
        if not events:
            return 0
        cutoff = now - window
        # trim + count in one pass
        keep = [t for t in events if t > cutoff]
        if len(keep) != len(events):
            cls._events[key] = keep
        return len(keep)

    @classmethod
    def _memory_record(cls, key: str, window: int) -> None:
        now = time.time()
        events = cls._events.setdefault(key, [])
        events.append(now)
        cutoff = now - window
        if len(events) > 1024:
            cls._events[key] = [t for t in events if t > cutoff]

    @classmethod
    async def charge(
        cls, operation: str, identifier: str, limit: int, window: int | None = None
    ) -> Tuple[bool, int]:
        """
        Charge one unit of *operation* against *identifier*.

        Returns (allowed, retry_after_seconds). allowed=False means the
        per-window budget for this identifier is exhausted.
        """
        if not identifier:
            return True, 0
        window = window or settings.COST_WINDOW_SECONDS
        key = cls._key(operation, identifier)
        now = time.time()

        client = await cls._get_redis()
        if client is not None:
            try:
                pipe = client.pipeline(transaction=True)
                pipe.zremrangebyscore(key, 0, now - window)
                pipe.zcard(key)
                current = await pipe.execute()[1]
                if int(current) >= limit:
                    oldest = await client.zrange(key, 0, 0, withscores=True)
                    retry_after = int(oldest[0][1] + window - now) if oldest else window
                    return False, max(retry_after, 1)
                pipe2 = client.pipeline(transaction=True)
                pipe2.zadd(key, {f"{now}:{cls._seq}": now})
                pipe2.expire(key, window + 60)
                await pipe2.execute()
                cls._seq += 1
                return True, 0
            except Exception as e:  # fall back to memory, never break the flow
                logger.error("cost_guard_redis_failed", operation=operation, error=str(e))

        # In-memory (authoritative when Redis is unavailable)
        count = cls._memory_count(key, window)
        if count >= limit:
            # retry after the oldest in-window event ages out
            events = sorted(cls._events.get(key, []))
            cutoff = now - window
            oldest = next((t for t in events if t > cutoff), now)
            return False, max(int(oldest + window - now), 1)
        cls._memory_record(key, window)
        return True, 0

    @classmethod
    async def check_budget(
        cls, operation: str, identifier: str, limit: int, window: int | None = None
    ) -> Tuple[bool, int]:
        """Non-charging check (peek). Use charge() at the point of the
        actual expensive action — charging AFTER the action is what
        makes the budget real."""
        if not identifier:
            return True, 0
        window = window or settings.COST_WINDOW_SECONDS
        key = cls._key(operation, identifier)
        now = time.time()

        client = await cls._get_redis()
        if client is not None:
            try:
                pipe = client.pipeline(transaction=True)
                pipe.zremrangebyscore(key, 0, now - window)
                pipe.zcard(key)
                current = await pipe.execute()[1]
                return int(current) < limit, 0
            except Exception:
                pass

        return cls._memory_count(key, window) < limit, 0

    @classmethod
    def record_abuse_alert(
        cls, operation: str, identifier: str, ip: str | None
    ) -> None:
        """Best-effort defense alert for an exhausted cost budget.

        Alerting must never break the request flow; the lazy import
        keeps the core layer free of middleware dependencies at
        import time. The alert is explainable: which operation, which
        identifier, and which budget was exhausted are all in the
        reasons.
        """
        try:
            from app.api.v1.middleware.defense_middleware import (
                record_security_alert,
            )

            record_security_alert(
                severity="medium",
                title="Cost abuse: cost budget exhausted",
                description=(
                    f"Per-identifier cost budget exhausted — "
                    f"operation={operation}, identifier={identifier}"
                ),
                source_ip=ip or "unknown",
                attack_type="cost_abuse",
                blocked=True,
                risk_score=0.6,
                confidence=0.85,
                reasons=[
                    f"per-identifier cost budget exhausted "
                    f"(operation={operation}, identifier={identifier})"
                ],
            )
        except Exception as e:  # noqa: BLE001 — alerting is best-effort
            logger.warning(
                "cost_abuse_alert_failed", operation=operation, error=str(e)
            )

    @classmethod
    def reset_all(cls) -> None:
        """Test isolation / ops reset (in-memory store only)."""
        cls._events.clear()
        cls._seq = 0
