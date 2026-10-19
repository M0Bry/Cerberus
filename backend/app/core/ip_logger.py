"""
IP Logger — IP + GeoIP + Device fingerprint + Browser fingerprint logging.

بيوفر:
- استخراج metadata العميل من الطلب
- تخزين تاريخ الطلبات في Redis
- حساب البيانات السلوكية (للطبقة الثانية)
- GeoIP lookup
- Device fingerprint
"""

import json
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import redis.asyncio as redis
import structlog

from app.core.config import settings

logger = structlog.get_logger()

# How often (seconds) we retry connecting to Redis after a failure.
_RECONNECT_INTERVAL = 15.0


class IPLogger:
    """
    كلاس لتسجيل IP والبيانات السلوكية.

    بيخزن في Redis:
    - تاريخ الطلبات لكل IP (List)
    - آخر وقت شوفنا فيه الـ IP
    - GeoIP info
    """

    _redis_client: Optional[redis.Redis] = None
    _last_redis_attempt: float = 0.0

    # In-memory mirror — behavioral data still feeds Tier 2 when Redis
    # is unavailable (single-process deployments, local dev, outages).
    _fallback_history: Dict[str, deque] = {}
    _fallback_last_seen: Dict[str, str] = {}
    _MAX_FALLBACK_IPS = 10_000

    # ─── Internal ──────────────────────────────────────────

    @classmethod
    def get_client(cls) -> Optional[redis.Redis]:
        """
        Lazy, throttled initialization للـ Redis client.

        Connects at most once every _RECONNECT_INTERVAL seconds; a
        failed command calls mark_redis_down() to cool down and let the
        in-memory mirror take over with zero added latency.
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
            logger.warning("ip_logger_redis_init_failed", error=str(e))
            return None

    @classmethod
    def mark_redis_down(cls) -> None:
        """Drop the cached client and cool down for _RECONNECT_INTERVAL."""
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
    def _build_key(client_ip: str, suffix: str = "history") -> str:
        """بتبني الـ Redis key."""
        return f"ip:{suffix}:{client_ip}"

    # ─── Public API ────────────────────────────────────────

    @staticmethod
    def extract_client_info(request) -> Dict[str, Any]:
        """
        استخراج كل الـ metadata المتاحة من الطلب.
        """
        ip = request.client.host if request.client else "unknown"

        # Real client IP: socket peer, EXCEPT when the peer is one of our
        # trusted proxies (TRUSTED_PROXY_CIDRS) — then the rightmost
        # untrusted X-Forwarded-For hop is used. From untrusted peers the
        # XFF header is client-controllable and ignored (anti-spoofing).
        from app.core.ip_resolver import resolve_client_ip

        real_ip = resolve_client_ip(
            request.client.host if request.client else None, request.headers
        )
        real_ip = real_ip or ip

        # User-Agent
        ua = request.headers.get("user-agent", "")
        try:
            from app.utils.user_agent import parse_user_agent
            ua_info = parse_user_agent(ua)
        except Exception:
            ua_info = {}

        # GeoIP (لو متاح)
        geo_info = {}
        try:
            from app.utils.geoip import get_geo_info
            geo_info = get_geo_info(real_ip) or {}
        except Exception:
            pass

        return {
            "ip_address": real_ip,
            "user_agent": ua[:500],
            "browser": ua_info.get("browser"),
            "browser_version": ua_info.get("browser_version"),
            "os": ua_info.get("os"),
            "os_version": ua_info.get("os_version"),
            "device": ua_info.get("device"),
            "accept_language": request.headers.get("accept-language", "")[:100],
            "referer": request.headers.get("referer", "")[:500],
            "method": request.method,
            "path": str(request.url.path),
            "query": str(request.url.query)[:500],
            "country": geo_info.get("country"),
            "city": geo_info.get("city"),
            "isp": geo_info.get("isp"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "unix_timestamp": time.time(),
        }

    @classmethod
    async def log_ip(cls, client_ip: str, info: Dict[str, Any]) -> None:
        """
        تسجيل طلب جديد في Redis.

        Args:
            client_ip: IP العميل
            info: metadata من extract_client_info
        """
        # In-memory mirror (always, bounded) — keeps Tier 2 fed even
        # when Redis is unavailable.
        history_dq = cls._fallback_history.get(client_ip)
        if history_dq is None:
            if len(cls._fallback_history) >= cls._MAX_FALLBACK_IPS:
                cls._fallback_history.pop(next(iter(cls._fallback_history)), None)
            history_dq = cls._fallback_history[client_ip] = deque()
        history_dq.appendleft(info)
        while len(history_dq) > settings.IP_LOGGER_MAX_HISTORY:
            history_dq.pop()
        cls._fallback_last_seen[client_ip] = info.get("timestamp", "")

        client = cls.get_client()
        if not client:
            return

        try:
            key = cls._build_key(client_ip, "history")

            # ضيف الطلب للـ List
            await client.lpush(key, json.dumps(info))

            # اقطع الـ List عند MAX_HISTORY
            await client.ltrim(key, 0, settings.IP_LOGGER_MAX_HISTORY - 1)

            # جدد وقت انتهاء الصلاحية
            await client.expire(key, settings.IP_LOGGER_TTL)

            # سجل آخر وقت
            last_seen_key = cls._build_key(client_ip, "last_seen")
            await client.setex(
                last_seen_key,
                settings.IP_LOGGER_TTL,
                info.get("timestamp", ""),
            )

        except Exception as e:
            logger.error("ip_logger_log_failed", error=str(e), ip=client_ip)
            cls.mark_redis_down()

    @classmethod
    async def get_history(
        cls,
        client_ip: str,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        بترجع تاريخ الطلبات لـ IP معين (Redis أو in-memory mirror).
        """
        client = cls.get_client()
        if not client:
            return list(cls._fallback_history.get(client_ip, []))[:limit]

        try:
            key = cls._build_key(client_ip, "history")
            entries = await client.lrange(key, 0, limit - 1)

            result = []
            for entry in entries:
                try:
                    result.append(json.loads(entry))
                except json.JSONDecodeError:
                    continue

            return result

        except Exception as e:
            logger.error("ip_logger_history_failed", error=str(e), ip=client_ip)
            cls.mark_redis_down()
            return list(cls._fallback_history.get(client_ip, []))[:limit]

    @classmethod
    async def get_behavioral_data(cls, client_ip: str) -> Dict[str, Any]:
        """
        بتحسب البيانات السلوكية لـ IP (للطبقة الثانية).

        Returns:
            Dict فيه:
            - request_count: عدد الطلبات
            - unique_endpoints: عدد المسارات الفريدة
            - unique_methods: عدد الـ methods الفريدة
            - avg_interval: متوسط الفترة بين الطلبات
            - error_rate: نسبة الأخطاء
            - time_of_day: وقت اليوم (0-23)
            - unique_user_agents: عدد الـ UAs الفريدة
            - unique_countries: عدد الدول الفريدة
        """
        history = await cls.get_history(client_ip)

        if not history:
            return {
                "request_count": 0,
                "unique_endpoints": 0,
                "unique_methods": 0,
                "avg_interval": 0.0,
                "error_rate": 0.0,
                "time_of_day": datetime.now(timezone.utc).hour,
                "unique_user_agents": 0,
                "unique_countries": 0,
            }

        # عدد الطلبات
        request_count = len(history)

        # المسارات الفريدة
        endpoints = [h.get("path", "") for h in history]
        unique_endpoints = len(set(endpoints))

        # الـ methods الفريدة
        methods = [h.get("method", "") for h in history]
        unique_methods = len(set(methods))

        # الـ User-Agents الفريدة
        user_agents = [h.get("user_agent", "") for h in history]
        unique_user_agents = len(set(user_agents))

        # الدول الفريدة
        countries = [h.get("country", "") for h in history if h.get("country")]
        unique_countries = len(set(countries))

        # متوسط الفترة بين الطلبات
        timestamps = [h.get("unix_timestamp", 0) for h in history if h.get("unix_timestamp")]
        if len(timestamps) > 1:
            timestamps.sort()
            intervals = [
                timestamps[i + 1] - timestamps[i]
                for i in range(len(timestamps) - 1)
            ]
            avg_interval = sum(intervals) / len(intervals) if intervals else 0.0
        else:
            avg_interval = 0.0

        # نسبة الأخطاء
        errors = sum(
            1 for h in history
            if h.get("status_code", 200) and h.get("status_code", 200) >= 400
        )
        error_rate = errors / request_count if request_count > 0 else 0.0

        # وقت اليوم
        time_of_day = datetime.now(timezone.utc).hour

        return {
            "request_count": request_count,
            "unique_endpoints": unique_endpoints,
            "unique_methods": unique_methods,
            "avg_interval": round(avg_interval, 3),
            "error_rate": round(error_rate, 3),
            "time_of_day": time_of_day,
            "unique_user_agents": unique_user_agents,
            "unique_countries": unique_countries,
        }

    @classmethod
    async def get_last_seen(cls, client_ip: str) -> Optional[str]:
        """بترجع آخر وقت شوفنا فيه الـ IP."""
        client = cls.get_client()
        if not client:
            return cls._fallback_last_seen.get(client_ip)

        try:
            key = cls._build_key(client_ip, "last_seen")
            last = await client.get(key)
            return last if last is not None else cls._fallback_last_seen.get(client_ip)
        except Exception as e:
            logger.error("ip_logger_last_seen_failed", error=str(e))
            cls.mark_redis_down()
            return cls._fallback_last_seen.get(client_ip)

    @classmethod
    def reset_all(cls) -> None:
        """Clear all in-memory IP state (test isolation / ops reset)."""
        cls._fallback_history.clear()
        cls._fallback_last_seen.clear()

    @classmethod
    async def clear(cls, client_ip: str) -> None:
        """بتمسح كل بيانات IP معين (Redis + in-memory mirror)."""
        cls._fallback_history.pop(client_ip, None)
        cls._fallback_last_seen.pop(client_ip, None)

        client = cls.get_client()
        if not client:
            return

        try:
            keys = [
                cls._build_key(client_ip, "history"),
                cls._build_key(client_ip, "last_seen"),
            ]
            await client.delete(*keys)
            logger.info("ip_logger_cleared", ip=client_ip)
        except Exception as e:
            logger.error("ip_logger_clear_failed", error=str(e), ip=client_ip)
            cls.mark_redis_down()

    @classmethod
    async def close(cls) -> None:
        """بتقفل اتصال Redis."""
        if cls._redis_client:
            try:
                await cls._redis_client.aclose()
            except AttributeError:
                await cls._redis_client.close()
            cls._redis_client = None