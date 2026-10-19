"""
Abuse Detector — Detects brute force, credential stuffing, and flooding.

بيوفر:
- Redis-backed counters (عشان يشتغل مع multiple workers)
- كشف Brute Force (محاولات دخول فاشلة)
- كشف Credential Stuffing (محاولات تسجيل متكررة)
- كشف Flooding (أخطاء 403 متكررة)
- حظر IP تلقائياً
- تسجيل الحوادث
"""

import time
import json
from collections import deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import redis.asyncio as redis
import structlog

from app.core.config import settings
from app.core.inmemory_store import ExpiringKeySet, WindowedEventLog

logger = structlog.get_logger()

# How often (seconds) we retry connecting to Redis after a failure.
_RECONNECT_INTERVAL = 15.0


class AbuseDetector:
    """
    كلاس لكشف السلوك المسيء باستخدام Redis.

    بيتبع:
    - محاولات تسجيل دخول فاشلة
    - محاولات تسجيل متكررة
    - أخطاء 403 متكررة
    - IPs محظورة
    """

    _redis_client: Optional[redis.Redis] = None
    _last_redis_attempt: float = 0.0

    # In-memory fallbacks — keep the abuse detector enforcing even when
    # Redis is unavailable (single-process deployments, local dev, outages).
    _fallback_events = WindowedEventLog()
    _fallback_blocks = ExpiringKeySet()
    _fallback_incidents: Dict[str, deque] = {}

    # ─── Internal ──────────────────────────────────────────

    @classmethod
    def get_client(cls) -> Optional[redis.Redis]:
        """
        Lazy, throttled initialization للـ Redis client.

        The client is constructed without I/O (redis.asyncio connects on
        first command), so a failure surfaces on the first real command;
        that path calls mark_redis_down(), which suppresses further
        attempts for _RECONNECT_INTERVAL seconds — requests then run
        against the in-memory fallbacks with zero added latency.
        """
        if cls._redis_client is not None:
            return cls._redis_client

        now = time.time()
        if now - cls._last_redis_attempt < _RECONNECT_INTERVAL:
            return None
        cls._last_redis_attempt = now

        try:
            cls._redis_client = redis.from_url(
                settings.REDIS_URL,
                decode_responses=True,
                socket_connect_timeout=2,
                socket_timeout=2,
            )
            return cls._redis_client
        except Exception as e:
            logger.warning("abuse_detector_redis_init_failed", error=str(e))
            return None

    @classmethod
    def mark_redis_down(cls) -> None:
        """
        Drop the cached client and cool down for _RECONNECT_INTERVAL.

        Called from the except-blocks below whenever a Redis command
        fails, so an outage never adds per-request connection latency
        and the in-memory fallbacks take over.
        """
        client, cls._redis_client = cls._redis_client, None
        if client is not None:
            try:
                import asyncio

                loop = asyncio.get_running_loop()
                loop.create_task(client.aclose())
            except Exception:
                pass
        cls._last_redis_attempt = time.time()

    @staticmethod
    def _build_key(suffix: str, identifier: str) -> str:
        """بتبني الـ Redis key."""
        return f"abuse:{suffix}:{identifier}"

    @classmethod
    async def _record_event(
        cls,
        key: str,
        window: int,
        max_entries: int = 1000,
    ) -> int:
        """
        بتسجل حدث وتعيد عدد الأحداث في النافذة الزمنية.

        Redis path uses a sorted set (score = timestamp) so counting is
        O(log n) instead of the old O(n) list-scan. Without Redis the
        in-memory WindowedEventLog applies the same window semantics.
        """
        client = cls.get_client()
        if not client:
            return cls._fallback_events.record(key, window)

        try:
            now = time.time()
            member = f"{now}:{id(now)}:{time.monotonic_ns()}"
            await client.zadd(key, {member: now})
            await client.zremrangebyscore(key, 0, now - window)
            await client.zremrangebyrank(key, 0, -max_entries - 1)
            await client.expire(key, window)
            return await client.zcard(key)

        except Exception as e:
            logger.error("abuse_detector_record_event_failed", error=str(e))
            cls.mark_redis_down()
            return cls._fallback_events.record(key, window)

    @classmethod
    async def _get_event_count(cls, key: str, window: int) -> int:
        """بترجع عدد الأحداث في النافذة الزمنية."""
        client = cls.get_client()
        if not client:
            return cls._fallback_events.count(key, window)

        try:
            now = time.time()
            await client.zremrangebyscore(key, 0, now - window)
            return await client.zcard(key)
        except Exception as e:
            logger.error("abuse_detector_get_count_failed", error=str(e))
            cls.mark_redis_down()
            return cls._fallback_events.count(key, window)

    # ─── Failed Login Tracking ─────────────────────────────

    @classmethod
    async def record_failed_login(cls, client_ip: str, email: str = "") -> Dict[str, Any]:
        """
        بتسجل محاولة دخول فاشلة.

        بتسجل على مستويين:
        - failed_logins:{ip}:{email} (لو فيه email) — لمتابعة نفس الإيميل
        - failed_logins:{ip} — لمتابعة كل محاولات الـ IP

        Returns:
            dict فيه:
            - failed_attempts: عدد المحاولات الفاشلة
            - is_locked_out: bool
            - is_abuse: bool
            - lockout_remaining_seconds: int
        """
        # 1. سجل على مستوى IP + email (لو فيه email)
        if email:
            per_email_key = cls._build_key("failed_logins", f"{client_ip}:{email}")
            await cls._record_event(
                per_email_key,
                window=settings.ABUSE_FAILED_LOGIN_WINDOW,
            )

        # 2. سجل على مستوى IP (دايماً)
        per_ip_key = cls._build_key("failed_logins", client_ip)
        count = await cls._record_event(
            per_ip_key,
            window=settings.ABUSE_FAILED_LOGIN_WINDOW,
        )

        is_locked_out = count >= settings.ABUSE_MAX_FAILED_LOGINS
        is_abuse = count >= settings.ABUSE_MAX_FAILED_LOGINS * 2

        if is_abuse:
            logger.warning(
                "abuse_detected_brute_force",
                ip=client_ip,
                email=email,
                attempts=count,
            )
            # احظر الـ IP
            await cls.block_ip(client_ip, duration=settings.ABUSE_BLOCK_DURATION)

        return {
            "failed_attempts": count,
            "is_locked_out": is_locked_out,
            "is_abuse": is_abuse,
            "lockout_remaining_seconds": (
                settings.ABUSE_FAILED_LOGIN_WINDOW if is_locked_out else 0
            ),
        }

    # ─── Register Attempt Tracking ─────────────────────────

    @classmethod
    async def record_register_attempt(cls, client_ip: str) -> Dict[str, Any]:
        """بتسجل محاولة تسجيل."""
        key = cls._build_key("register_attempts", client_ip)

        count = await cls._record_event(
            key,
            window=settings.ABUSE_FAILED_LOGIN_WINDOW,
        )

        is_abuse = count >= 5

        if is_abuse:
            logger.warning(
                "abuse_detected_register_flood",
                ip=client_ip,
                attempts=count,
            )

        return {
            "attempts": count,
            "is_abuse": is_abuse,
        }

    # ─── Verify Attempt Tracking ───────────────────────────

    @classmethod
    async def record_verify_attempt(cls, client_ip: str) -> Dict[str, Any]:
        """بتسجل محاولة تحقق (OTP)."""
        key = cls._build_key("verify_attempts", client_ip)

        count = await cls._record_event(
            key,
            window=settings.ABUSE_FAILED_LOGIN_WINDOW,
        )

        is_abuse = count >= 10

        if is_abuse:
            logger.warning(
                "abuse_detected_verify_flood",
                ip=client_ip,
                attempts=count,
            )

        return {
            "attempts": count,
            "is_abuse": is_abuse,
        }

    # ─── Forbidden (403) Tracking ──────────────────────────

    @classmethod
    async def record_forbidden(cls, client_ip: str) -> int:
        """بتسجل خطأ 403 وترجع العدد الحالي."""
        key = cls._build_key("forbidden_errors", client_ip)

        count = await cls._record_event(
            key,
            window=settings.ABUSE_FORBIDDEN_WINDOW,
        )

        return count

    # ─── Abuse Detection ───────────────────────────────────

    @classmethod
    async def _count_failed_logins_for_ip(cls, client_ip: str) -> int:
        """
        بتعد كل محاولات الدخول الفاشلة لـ IP معين.
        بتستخدم SCAN عشان تلاقي كل الـ keys اللي بتبدأ بـ
        failed_logins:{ip} (بما فيها :{email}).
        """
        # The per-IP key already counts every failure from this IP
        # (record_failed_login writes it on each attempt), so it is the
        # authoritative total. The per-email keys (failed_logins:{ip}:{email})
        # add granularity for forensics but must NOT be summed on top —
        # doing so would double-count every failure and lock users out
        # after only ~3 wrong passwords.
        per_ip_key = cls._build_key("failed_logins", client_ip)
        client = cls.get_client()
        if not client:
            return cls._fallback_events.count(
                per_ip_key,
                settings.ABUSE_FAILED_LOGIN_WINDOW,
            )

        try:
            return await cls._get_event_count(
                per_ip_key,
                window=settings.ABUSE_FAILED_LOGIN_WINDOW,
            )

        except Exception as e:
            logger.error("abuse_detector_count_failed_logins_failed", error=str(e))
            cls.mark_redis_down()
            return cls._fallback_events.count(
                per_ip_key,
                settings.ABUSE_FAILED_LOGIN_WINDOW,
            )

    @classmethod
    async def is_abusive(cls, client_ip: str, endpoint: str = "") -> bool:
        """
        بتفحص لو الـ IP مسيء.

        Returns:
            True لو مسيء، False لو لأ.
        """
        # 1. فحص لو الـ IP محظور (Redis أو in-memory)
        blocked_key = cls._build_key("blocked", client_ip)
        client = cls.get_client()
        if client is not None:
            try:
                is_blocked = bool(await client.get(blocked_key))
            except Exception:
                cls.mark_redis_down()
                is_blocked = cls._fallback_blocks.is_blocked(blocked_key)
        else:
            is_blocked = cls._fallback_blocks.is_blocked(blocked_key)

        if is_blocked:
            logger.warning("blocked_ip_attempt", ip=client_ip, endpoint=endpoint)
            return True

        # 2. فحص محاولات الدخول الفاشلة (كل الـ emails)
        #    (helper handles Redis vs in-memory internally)
        failed_count = await cls._count_failed_logins_for_ip(client_ip)
        if failed_count >= settings.ABUSE_MAX_FAILED_LOGINS:
            logger.warning(
                "abusive_ip_failed_logins",
                ip=client_ip,
                count=failed_count,
            )
            return True

        # 3. فحص أخطاء 403
        forbidden_key = cls._build_key("forbidden_errors", client_ip)
        forbidden_count = await cls._get_event_count(
            forbidden_key,
            window=settings.ABUSE_FORBIDDEN_WINDOW,
        )
        if forbidden_count >= settings.ABUSE_MAX_403_ERRORS:
            logger.warning(
                "abusive_ip_403_errors",
                ip=client_ip,
                count=forbidden_count,
            )
            return True

        return False

    # ─── Blocking ──────────────────────────────────────────

    @classmethod
    async def block_ip(cls, client_ip: str, duration: int = None) -> None:
        """بتحظر IP لمدة معينة (Redis + in-memory, so both views agree)."""
        duration = duration or settings.ABUSE_BLOCK_DURATION
        key = cls._build_key("blocked", client_ip)

        # Always record locally — cheap, and keeps the block effective
        # even if Redis is down or comes back later.
        cls._fallback_blocks.add(key, duration)

        client = cls.get_client()
        if not client:
            logger.warning("ip_blocked", ip=client_ip, duration=duration, backend="memory")
            return

        try:
            await client.setex(key, duration, "1")
            logger.warning("ip_blocked", ip=client_ip, duration=duration)
        except Exception as e:
            logger.error("abuse_detector_block_failed", error=str(e))
            cls.mark_redis_down()

    @classmethod
    async def unblock_ip(cls, client_ip: str) -> None:
        """بفك حظر IP (from both Redis and the in-memory blocklist)."""
        key = cls._build_key("blocked", client_ip)
        cls._fallback_blocks.remove(key)

        client = cls.get_client()
        if not client:
            logger.info("ip_unblocked", ip=client_ip)
            return

        try:
            await client.delete(key)
            logger.info("ip_unblocked", ip=client_ip)
        except Exception as e:
            logger.error("abuse_detector_unblock_failed", error=str(e))
            cls.mark_redis_down()

    @classmethod
    async def is_blocked(cls, client_ip: str) -> bool:
        """بتفحص لو الـ IP محظور (Redis أو in-memory)."""
        key = cls._build_key("blocked", client_ip)
        client = cls.get_client()

        if client is not None:
            try:
                blocked = (await client.exists(key)) > 0
            except Exception as e:
                logger.error("abuse_detector_is_blocked_failed", error=str(e))
                cls.mark_redis_down()
                return cls._fallback_blocks.is_blocked(key)
            # Keep the local mirror in sync on the happy path.
            if blocked:
                ttl = await client.ttl(key)
                if ttl and ttl > 0:
                    cls._fallback_blocks.add(key, ttl)
                return True
            return False

        return cls._fallback_blocks.is_blocked(key)

    # ─── Incident Logging ──────────────────────────────────

    @classmethod
    async def record_incident(
        cls,
        client_ip: str,
        incident_type: str,
        details: str = "",
    ) -> None:
        """بتسجل حادثة (Redis + in-memory mirror for the dashboard)."""
        key = cls._build_key("incidents", client_ip)
        incident = {
            "type": incident_type,
            "details": details[:500],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "unix_timestamp": time.time(),
        }

        # In-memory mirror (always, bounded).
        dq = cls._fallback_incidents.setdefault(key, deque())
        dq.appendleft(incident)
        while len(dq) > settings.INCIDENT_MAX_HISTORY:
            dq.pop()

        client = cls.get_client()
        if not client:
            logger.warning(
                "incident_recorded",
                ip=client_ip,
                type=incident_type,
                details=details[:100],
                backend="memory",
            )
            return

        try:
            await client.lpush(key, json.dumps(incident))
            await client.ltrim(key, 0, settings.INCIDENT_MAX_HISTORY - 1)
            await client.expire(key, settings.INCIDENT_TTL)

            logger.warning(
                "incident_recorded",
                ip=client_ip,
                type=incident_type,
                details=details[:100],
            )
        except Exception as e:
            logger.error("abuse_detector_record_incident_failed", error=str(e))
            cls.mark_redis_down()

    @classmethod
    async def get_incidents(
        cls,
        client_ip: str,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """بترجع حوادث IP معين (Redis أو in-memory mirror)."""
        key = cls._build_key("incidents", client_ip)
        client = cls.get_client()

        if client is None:
            return list(cls._fallback_incidents.get(key, []))[:limit]

        try:
            entries = await client.lrange(key, 0, limit - 1)

            result = []
            for entry in entries:
                try:
                    result.append(json.loads(entry))
                except json.JSONDecodeError:
                    continue
            return result
        except Exception as e:
            logger.error("abuse_detector_get_incidents_failed", error=str(e))
            cls.mark_redis_down()
            return list(cls._fallback_incidents.get(key, []))[:limit]

    # ─── Bulk Operations (للـ Admin / Dashboard) ──────────

    @classmethod
    async def get_all_blocked_ips(cls) -> List[Dict[str, Any]]:
        """
        بترجع كل الـ IPs المحظورة.

        بتستخدم SCAN عشان تلاقي كل الـ keys اللي بتبدأ بـ abuse:blocked:
        """
        client = cls.get_client()
        if not client:
            prefix = cls._build_key("blocked", "")
            return [
                {
                    "ip": key.replace(prefix, ""),
                    "expires_in": ttl,
                    "blocked": True,
                }
                for key, ttl in cls._fallback_blocks.all_blocked()
            ]

        try:
            blocked = []
            pattern = cls._build_key("blocked", "*")

            async for key in client.scan_iter(match=pattern, count=100):
                # استخرج الـ IP من الـ key
                # key = "abuse:blocked:192.168.1.1"
                prefix = cls._build_key("blocked", "")
                ip = key.replace(prefix, "")

                # جيب الـ TTL
                ttl = await client.ttl(key)

                blocked.append({
                    "ip": ip,
                    "expires_in": max(0, ttl),
                    "blocked": True,
                })

            return blocked

        except Exception as e:
            logger.error("abuse_detector_get_all_blocked_ips_failed", error=str(e))
            cls.mark_redis_down()
            prefix = cls._build_key("blocked", "")
            return [
                {
                    "ip": key.replace(prefix, ""),
                    "expires_in": ttl,
                    "blocked": True,
                }
                for key, ttl in cls._fallback_blocks.all_blocked()
            ]

    @classmethod
    async def get_all_incidents(
        cls,
        limit_per_ip: int = 10,
    ) -> List[Dict[str, Any]]:
        """
        بترجع كل الحوادث من كل الـ IPs.

        Args:
            limit_per_ip: أقصى عدد حوادث لكل IP
        """
        client = cls.get_client()
        if not client:
            # In-memory mirror path.
            prefix = cls._build_key("incidents", "")
            all_incidents = []
            for key, dq in cls._fallback_incidents.items():
                ip = key.replace(prefix, "")
                for incident in list(dq)[:limit_per_ip]:
                    all_incidents.append({**incident, "ip": ip})
            all_incidents.sort(
                key=lambda x: x.get("unix_timestamp", 0),
                reverse=True,
            )
            return all_incidents

        try:
            all_incidents = []
            pattern = cls._build_key("incidents", "*")
            prefix = cls._build_key("incidents", "")

            async for key in client.scan_iter(match=pattern, count=100):
                ip = key.replace(prefix, "")
                entries = await client.lrange(key, 0, limit_per_ip - 1)

                for entry in entries:
                    try:
                        incident = json.loads(entry)
                        incident["ip"] = ip
                        all_incidents.append(incident)
                    except json.JSONDecodeError:
                        continue

            # رتب حسب الـ timestamp (الأحدث أول)
            all_incidents.sort(
                key=lambda x: x.get("unix_timestamp", 0),
                reverse=True,
            )

            return all_incidents

        except Exception as e:
            logger.error("abuse_detector_get_all_incidents_failed", error=str(e))
            cls.mark_redis_down()
            prefix = cls._build_key("incidents", "")
            all_incidents = []
            for key, dq in cls._fallback_incidents.items():
                ip = key.replace(prefix, "")
                for incident in list(dq)[:limit_per_ip]:
                    all_incidents.append({**incident, "ip": ip})
            all_incidents.sort(
                key=lambda x: x.get("unix_timestamp", 0),
                reverse=True,
            )
            return all_incidents

    # ─── Utility ───────────────────────────────────────────

    @classmethod
    def reset_all(cls) -> None:
        """
        Clear all in-memory abuse state (test isolation / ops reset).

        Redis state is left untouched — use the API endpoints for that.
        """
        cls._fallback_events.reset_all()
        cls._fallback_blocks.reset_all()
        cls._fallback_incidents.clear()

    @classmethod
    async def clear(cls, client_ip: str) -> None:
        """بتمسح كل بيانات IP معين."""
        client = cls.get_client()
        if not client:
            return

        try:
            keys = [
                cls._build_key("blocked", client_ip),
                cls._build_key("failed_logins", client_ip),
                cls._build_key("register_attempts", client_ip),
                cls._build_key("verify_attempts", client_ip),
                cls._build_key("forbidden_errors", client_ip),
                cls._build_key("incidents", client_ip),
            ]

            # كمان امسح كل الـ keys اللي بتبدأ بـ failed_logins:{ip}:
            pattern = cls._build_key("failed_logins", f"{client_ip}:*")
            async for key in client.scan_iter(match=pattern, count=100):
                keys.append(key)

            await client.delete(*keys)
            logger.info("abuse_detector_cleared", ip=client_ip)
        except Exception as e:
            logger.error("abuse_detector_clear_failed", error=str(e))

    @classmethod
    async def close(cls) -> None:
        """بتقفل اتصال Redis."""
        if cls._redis_client:
            try:
                await cls._redis_client.aclose()
            except AttributeError:
                await cls._redis_client.close()
            cls._redis_client = None