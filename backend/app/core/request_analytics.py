"""
Request Analytics — Collects and analyzes request patterns.

بيوفر:
- Request rate (req/s)
- Path distribution
- Status code distribution
- Method distribution
- Time distribution
- Top endpoints, top errors
- Behavioral patterns
- Redis-backed (stats aggregation)

الفكرة:
- نجمع إحصائيات لكل IP
- نخزنها في Redis (Hashes)
- نحللها عند الطلب

الاستخدام:
- Dashboard
- Behavioral Analysis (Tier 2)
- Anomaly Detection
- Rate Limiting
"""

import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import redis.asyncio as redis
import structlog

from app.core.config import settings

logger = structlog.get_logger()


class RequestAnalytics:
    """
    Request Analytics Collector.

    الفكرة:
    - نجمع إحصائيات لكل IP
    - نخزن في Redis Hashes
    - نحللها عند الطلب
    """

    _redis_client: Optional[redis.Redis] = None

    # ─── Config ────────────────────────────────────────────
    STATS_TTL = 86400 * 7  # 7 أيام
    MAX_HISTORY = 1000
    MIN_WINDOW_SECONDS = 60  # 60 ثانية كحد أدنى لحساب المعدل

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
                logger.error("request_analytics_redis_init_failed", error=str(e))
                return None
        return cls._redis_client

    # ─── Recording ─────────────────────────────────────────

    @classmethod
    async def record(
        cls,
        client_ip: str,
        path: str,
        method: str,
        status_code: int,
        response_time_ms: float = 0,
    ) -> None:
        """
        بيسجل طلب جديد لتحليل الإحصائيات.

        Args:
            client_ip: IP
            path: المسار
            method: HTTP Method
            status_code: رمز الرد
            response_time_ms: وقت المعالجة
        """
        client = cls.get_client()
        if not client:
            return

        try:
            now = time.time()
            hour_key = datetime.now(timezone.utc).strftime("%Y-%m-%d-%H")

            # 1. العدادات الأساسية
            pipe = client.pipeline()

            # إجمالي الطلبات
            pipe.hincrby(f"analytics:{client_ip}", "total_requests", 1)

            # الوقت
            pipe.hset(f"analytics:{client_ip}", "last_request", str(now))
            pipe.hsetnx(f"analytics:{client_ip}", "first_request", str(now))

            # 2. توزيع الـ Methods
            pipe.hincrby(f"analytics:{client_ip}:methods", method, 1)

            # 3. توزيع الـ Status Codes
            pipe.hincrby(f"analytics:{client_ip}:status", str(status_code), 1)

            # 4. توزيع المسارات (hash بس، مش النص الكامل)
            path_hash = hashlib.md5(path.encode()).hexdigest()[:8]
            pipe.hincrby(f"analytics:{client_ip}:paths", path_hash, 1)

            # 5. توزيع الساعات
            pipe.hincrby(f"analytics:{client_ip}:hours", hour_key, 1)

            # 6. عداد الأخطاء
            if status_code >= 400:
                pipe.hincrby(f"analytics:{client_ip}", "errors", 1)
                if status_code == 404:
                    pipe.hincrby(f"analytics:{client_ip}", "errors_404", 1)
                elif status_code == 403:
                    pipe.hincrby(f"analytics:{client_ip}", "errors_403", 1)
                elif status_code == 429:
                    pipe.hincrby(f"analytics:{client_ip}", "errors_429", 1)

            # 7. وقت الاستجابة
            if response_time_ms > 0:
                pipe.hincrbyfloat(
                    f"analytics:{client_ip}",
                    "total_response_time",
                    response_time_ms,
                )
                pipe.hincrby(f"analytics:{client_ip}", "response_count", 1)

            # 8. TTL
            pipe.expire(f"analytics:{client_ip}", cls.STATS_TTL)
            pipe.expire(f"analytics:{client_ip}:methods", cls.STATS_TTL)
            pipe.expire(f"analytics:{client_ip}:status", cls.STATS_TTL)
            pipe.expire(f"analytics:{client_ip}:paths", cls.STATS_TTL)
            pipe.expire(f"analytics:{client_ip}:hours", cls.STATS_TTL)

            await pipe.execute()

        except Exception as e:
            logger.error("request_analytics_record_failed", error=str(e))

    # ─── Analysis ──────────────────────────────────────────

    @classmethod
    async def get_stats(cls, client_ip: str) -> Dict[str, Any]:
        """
        بترجع إحصائيات IP.

        Returns:
            dict فيه:
            - total_requests
            - errors
            - errors_404
            - errors_403
            - errors_429
            - error_rate
            - first_seen
            - last_seen
            - session_duration
            - avg_response_time
            - methods (dict)
            - status_codes (dict)
            - hours (dict)
            - unique_paths
            - requests_per_hour
        """
        client = cls.get_client()
        if not client:
            return cls._empty_stats()

        try:
            # 1. جيب العدادات الأساسية
            data = await client.hgetall(f"analytics:{client_ip}")
            methods = await client.hgetall(f"analytics:{client_ip}:methods")
            status = await client.hgetall(f"analytics:{client_ip}:status")
            paths = await client.hgetall(f"analytics:{client_ip}:paths")
            hours = await client.hgetall(f"analytics:{client_ip}:hours")

            if not data:
                return cls._empty_stats()

            # 2. احسب الأساسيات
            total_requests = int(data.get("total_requests", 0))
            errors = int(data.get("errors", 0))
            errors_404 = int(data.get("errors_404", 0))
            errors_403 = int(data.get("errors_403", 0))
            errors_429 = int(data.get("errors_429", 0))

            first_request = float(data.get("first_request", 0))
            last_request = float(data.get("last_request", 0))

            # 3. نسبة الأخطاء
            error_rate = errors / total_requests if total_requests > 0 else 0

            # 4. مدة الجلسة
            session_duration = last_request - first_request if first_request > 0 else 0

            # 5. متوسط وقت الاستجابة
            total_response_time = float(data.get("total_response_time", 0))
            response_count = int(data.get("response_count", 0))
            avg_response_time = (
                total_response_time / response_count
                if response_count > 0 else 0
            )

            # 6. عدد المسارات الفريدة
            unique_paths = len(paths)

            # 7. معدل الطلبات
            # ملاحظة مهمة: بنستخدم MIN_WINDOW_SECONDS كحد أدنى
            # عشان نتجنب الأرقام الضخمة لما الطلبات تتجمع في ثانية
            now = time.time()
            if first_request > 0:
                actual_duration = now - first_request
                effective_duration = max(actual_duration, cls.MIN_WINDOW_SECONDS)
                hours_active = effective_duration / 3600
                requests_per_hour = total_requests / hours_active
            else:
                requests_per_hour = 0.0

            # 8. أكثر المسارات
            top_paths = sorted(
                [(k, int(v)) for k, v in paths.items()],
                key=lambda x: x[1],
                reverse=True,
            )[:5]

            # 9. أكثر الساعات
            top_hours = sorted(
                [(k, int(v)) for k, v in hours.items()],
                key=lambda x: x[1],
                reverse=True,
            )[:5]

            return {
                "ip": client_ip,
                "total_requests": total_requests,
                "errors": errors,
                "errors_404": errors_404,
                "errors_403": errors_403,
                "errors_429": errors_429,
                "error_rate": round(error_rate, 3),
                "first_seen": first_request,
                "last_seen": last_request,
                "session_duration": round(session_duration, 2),
                "avg_response_time": round(avg_response_time, 2),
                "methods": {k: int(v) for k, v in methods.items()},
                "status_codes": {k: int(v) for k, v in status.items()},
                "hours": {k: int(v) for k, v in hours.items()},
                "unique_paths": unique_paths,
                "requests_per_hour": round(requests_per_hour, 2),
                "top_paths": top_paths,
                "top_hours": top_hours,
            }

        except Exception as e:
            logger.error("request_analytics_get_stats_failed", error=str(e))
            return cls._empty_stats()

    @classmethod
    def _empty_stats(cls) -> Dict[str, Any]:
        """إحصائيات فاضية."""
        return {
            "ip": None,
            "total_requests": 0,
            "errors": 0,
            "errors_404": 0,
            "errors_403": 0,
            "errors_429": 0,
            "error_rate": 0.0,
            "first_seen": 0.0,
            "last_seen": 0.0,
            "session_duration": 0.0,
            "avg_response_time": 0.0,
            "methods": {},
            "status_codes": {},
            "hours": {},
            "unique_paths": 0,
            "requests_per_hour": 0.0,
            "top_paths": [],
            "top_hours": [],
        }

    # ─── Pattern Detection ─────────────────────────────────

    @classmethod
    async def detect_patterns(cls, client_ip: str) -> Dict[str, Any]:
        """
        بيكشف أنماط السلوك.

        Returns:
            dict فيه:
            - is_scanner: bool (بيبحث على مسارات كتير)
            - is_brute_forcer: bool (محاولات فاشلة كتير)
            - is_ddos: bool (معدل عالي)
            - is_night_owl: bool (بيشتغل بالليل)
            - patterns: list of detected patterns
        """
        stats = await cls.get_stats(client_ip)

        if stats["total_requests"] == 0:
            return {
                "is_scanner": False,
                "is_brute_forcer": False,
                "is_ddos": False,
                "is_night_owl": False,
                "patterns": [],
            }

        patterns: List[str] = []

        # 1. Scanner detection
        # - مسارات فريدة كتير
        # - 404 errors كتير
        is_scanner = False
        if stats["unique_paths"] > 20 and stats["errors_404"] > 10:
            is_scanner = True
            patterns.append("scanner_behavior")

        # 2. Brute forcer detection
        # - 403 أو 401 errors كتير
        is_brute_forcer = False
        if stats["errors_403"] > 20:
            is_brute_forcer = True
            patterns.append("brute_force_behavior")

        # 3. DDoS detection
        # - معدل طلبات عالي جداً (> 6000 req/hour = 100/min)
        # ملاحظة: الـ rate بيستخدم MIN_WINDOW_SECONDS عشان يتجنب الـ false positives
        is_ddos = False
        if stats["requests_per_hour"] > 6000:  # 100/min
            is_ddos = True
            patterns.append("ddos_behavior")

        # 4. Night owl
        # - معظم الطلبات بين 12 ص و 6 ص
        is_night_owl = False
        if stats["top_hours"]:
            night_hours = 0
            total = sum(count for _, count in stats["top_hours"])
            for hour_key, count in stats["top_hours"]:
                try:
                    hour = int(hour_key.split("-")[-1])
                    if 0 <= hour <= 6:
                        night_hours += count
                except (ValueError, IndexError):
                    continue

            if total > 0 and (night_hours / total) > 0.7:
                is_night_owl = True
                patterns.append("night_activity")

        return {
            "is_scanner": is_scanner,
            "is_brute_forcer": is_brute_forcer,
            "is_ddos": is_ddos,
            "is_night_owl": is_night_owl,
            "patterns": patterns,
        }

    # ─── Top IPs ───────────────────────────────────────────

    @classmethod
    async def get_top_ips(
        cls,
        limit: int = 10,
        by: str = "requests",
    ) -> List[Dict[str, Any]]:
        """
        بترجع أكثر IPs نشاطاً.

        Args:
            limit: عدد النتائج
            by: requests / errors / rate

        Returns:
            list of dicts
        """
        client = cls.get_client()
        if not client:
            return []

        try:
            # جمع كل الـ IPs
            top_ips: List[Tuple[str, int]] = []

            async for key in client.scan_iter(match="analytics:*", count=100):
                # استثني الـ keys الفرعية
                parts = key.split(":")
                if len(parts) != 2:
                    continue

                ip = parts[1]
                data = await client.hgetall(key)

                if by == "requests":
                    value = int(data.get("total_requests", 0))
                elif by == "errors":
                    value = int(data.get("errors", 0))
                else:
                    value = int(data.get("total_requests", 0))

                top_ips.append((ip, value))

            # رتب
            top_ips.sort(key=lambda x: x[1], reverse=True)

            return [
                {"ip": ip, "value": value}
                for ip, value in top_ips[:limit]
            ]

        except Exception as e:
            logger.error("request_analytics_top_ips_failed", error=str(e))
            return []

    # ─── Global Stats ──────────────────────────────────────

    @classmethod
    async def get_global_stats(cls) -> Dict[str, Any]:
        """
        بترجع إحصائيات عامة (لكل النظام).

        Returns:
            dict فيه:
            - total_ips
            - total_requests
            - total_errors
            - avg_error_rate
            - top_methods
            - top_status_codes
        """
        client = cls.get_client()
        if not client:
            return cls._empty_global_stats()

        try:
            total_ips = 0
            total_requests = 0
            total_errors = 0
            all_methods: Dict[str, int] = {}
            all_status: Dict[str, int] = {}

            async for key in client.scan_iter(match="analytics:*", count=100):
                parts = key.split(":")
                if len(parts) != 2:
                    continue

                total_ips += 1
                data = await client.hgetall(key)

                total_requests += int(data.get("total_requests", 0))
                total_errors += int(data.get("errors", 0))

            # جمع الـ methods و status
            async for key in client.scan_iter(
                match="analytics:*:methods", count=100
            ):
                methods = await client.hgetall(key)
                for k, v in methods.items():
                    all_methods[k] = all_methods.get(k, 0) + int(v)

            async for key in client.scan_iter(
                match="analytics:*:status", count=100
            ):
                status = await client.hgetall(key)
                for k, v in status.items():
                    all_status[k] = all_status.get(k, 0) + int(v)

            avg_error_rate = (
                total_errors / total_requests if total_requests > 0 else 0
            )

            return {
                "total_ips": total_ips,
                "total_requests": total_requests,
                "total_errors": total_errors,
                "avg_error_rate": round(avg_error_rate, 3),
                "top_methods": dict(
                    sorted(all_methods.items(), key=lambda x: x[1], reverse=True)[:5]
                ),
                "top_status_codes": dict(
                    sorted(all_status.items(), key=lambda x: x[1], reverse=True)[:5]
                ),
            }

        except Exception as e:
            logger.error("request_analytics_global_stats_failed", error=str(e))
            return cls._empty_global_stats()

    @classmethod
    def _empty_global_stats(cls) -> Dict[str, Any]:
        """إحصائيات عامة فاضية."""
        return {
            "total_ips": 0,
            "total_requests": 0,
            "total_errors": 0,
            "avg_error_rate": 0.0,
            "top_methods": {},
            "top_status_codes": {},
        }

    # ─── Utilities ─────────────────────────────────────────

    @classmethod
    async def clear(cls, client_ip: Optional[str] = None) -> None:
        """بيمسح إحصائيات IP أو كل الإحصائيات."""
        client = cls.get_client()
        if not client:
            return

        try:
            if client_ip:
                keys = [
                    f"analytics:{client_ip}",
                    f"analytics:{client_ip}:methods",
                    f"analytics:{client_ip}:status",
                    f"analytics:{client_ip}:paths",
                    f"analytics:{client_ip}:hours",
                ]
                await client.delete(*keys)
                logger.info("request_analytics_cleared", ip=client_ip)
            else:
                async for key in client.scan_iter(match="analytics:*", count=100):
                    await client.delete(key)
                logger.info("request_analytics_cleared_all")
        except Exception as e:
            logger.error("request_analytics_clear_failed", error=str(e))

    @classmethod
    async def close(cls) -> None:
        """بتقفل Redis."""
        if cls._redis_client:
            await cls._redis_client.close()
            cls._redis_client = None