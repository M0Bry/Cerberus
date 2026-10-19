"""
Scraping Detector — Detects web scraping / crawling bots.

بيوفر:
- High request rate detection
- Sequential path traversal detection
- Static asset ratio analysis
- Deep crawling detection
- Referer analysis
- Timing uniformity detection
- Suspicious user agent detection
- Risk scoring
- Redis-backed

الفكرة:
- نتتبع كل request (path, ip, ua, referer, timestamp)
- نحلل أنماط الزيارة
- نحسب risk score

الاستخدام:
- Anti-scraping
- Content protection
- Resource protection
- Bot detection
"""

import math
import re
import statistics
import time
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

import redis.asyncio as redis
import structlog

from app.core.config import settings

logger = structlog.get_logger()


class ScrapingDetector:
    """
    Web Scraping Detector.

    الفكرة:
    - نتتبع requests لكل IP
    - نحلل الأنماط (timing, paths, assets)
    - نحسب risk score
    """

    _redis_client: Optional[redis.Redis] = None

    # ─── Config ────────────────────────────────────────────
    WINDOW_TTL = 3600            # ساعة
    MAX_REQUESTS_TRACKED = 500   # لكل IP

    # ─── Thresholds ────────────────────────────────────────
    HIGH_REQUEST_RATE = 60       # طلب/دقيقة
    VERY_HIGH_RATE = 200         # طلب/دقيقة
    DEEP_CRAWL_THRESHOLD = 50    # عدد مسارات مختلفة
    STATIC_ASSET_MIN_RATIO = 0.2 # المفروض 20% على الأقل static
    SEQUENTIAL_MIN_COUNT = 5     # 5 مسارات متتالية
    UNIFORM_TIMING_CV = 0.15     # coefficient of variation

    # ─── Risk Weights ─────────────────────────────────────
    WEIGHTS = {
        "high_request_rate": 35,
        "very_high_rate": 45,
        "no_static_assets": 25,
        "deep_crawling": 30,
        "sequential_traversal": 40,
        "missing_referer": 15,
        "uniform_timing": 30,
        "suspicious_user_agent": 20,
        "parameter_enumeration": 45,
        "known_scraper_ua": 50,
    }

    # ─── Risk Thresholds ──────────────────────────────────
    THRESHOLDS = {
        "low": 30,
        "medium": 50,
        "high": 70,
        "critical": 85,
    }

    # ─── Static Asset Extensions ──────────────────────────
    STATIC_EXTENSIONS = {
        ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
        ".webp", ".ico", ".woff", ".woff2", ".ttf", ".eot",
        ".mp4", ".webm", ".mp3", ".pdf", ".zip",
    }

    # ─── Suspicious User Agents ───────────────────────────
    SCRAPER_UA_FRAGMENTS = [
        "scrapy", "curl", "wget", "python-requests", "python-urllib",
        "go-http-client", "java/", "libwww-perl", "okhttp",
        "httpclient", "axios/", "postmanruntime", "httpie",
        "mechanize", "phantomjs", "headlesschrome",
        "bot", "crawler", "spider", "scraper",
    ]

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
                logger.error("scraping_detector_redis_init_failed", error=str(e))
                return None
        return cls._redis_client

    # ─── Key Helpers ───────────────────────────────────────

    @staticmethod
    def _requests_key(ip: str) -> str:
        return f"scraping:ip:{ip}:requests"

    @staticmethod
    def _paths_key(ip: str) -> str:
        return f"scraping:ip:{ip}:paths"

    @staticmethod
    def _stats_key(ip: str) -> str:
        return f"scraping:ip:{ip}:stats"

    # ─── Helpers ───────────────────────────────────────────

    @staticmethod
    def _is_static_asset(path: str) -> bool:
        """بيكشف لو المسار static asset."""
        if not path:
            return False

        path_lower = path.lower().split("?")[0]

        for ext in ScrapingDetector.STATIC_EXTENSIONS:
            if path_lower.endswith(ext):
                return True

        return False

    @staticmethod
    def _extract_numeric_id(path: str) -> Optional[int]:
        """
        بيستخرج ID رقمي من المسار.

        مثال: /product/123 → 123
              /user/456/profile → 456
        """
        if not path:
            return None

        # شيل query string
        clean_path = path.split("?")[0]

        # دور على أرقام
        matches = re.findall(r"/(\d+)(?:/|$)", clean_path)

        if matches:
            try:
                return int(matches[-1])
            except (ValueError, IndexError):
                return None

        return None

    @staticmethod
    def _normalize_path(path: str) -> str:
        """
        بيطبع المسار لشكل موحد.

        مثال: /product/123 → /product/{id}
              /user/456 → /user/{id}

        ملاحظة: الدالة دي محفوظة للاستخدام المستقبلي
        (مش مستخدمة في record_request حالياً).
        """
        if not path:
            return ""

        clean_path = path.split("?")[0]

        # استبدل الأرقام بـ {id}
        normalized = re.sub(r"/\d+", "/{id}", clean_path)

        # استبدل UUIDs
        normalized = re.sub(
            r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "/{uuid}",
            normalized,
            flags=re.IGNORECASE,
        )

        return normalized

    @classmethod
    def _is_suspicious_ua(cls, user_agent: Optional[str]) -> bool:
        """بيكشف لو الـ UA مشبوه."""
        if not user_agent:
            return True

        ua_lower = user_agent.lower()
        for fragment in cls.SCRAPER_UA_FRAGMENTS:
            if fragment in ua_lower:
                return True

        return False

    # ─── Recording ─────────────────────────────────────────

    @classmethod
    async def record_request(
        cls,
        ip: str,
        path: str,
        user_agent: Optional[str] = None,
        referer: Optional[str] = None,
        method: str = "GET",
    ) -> None:
        """
        بيسجل request.

        Args:
            ip: IP
            path: المسار
            user_agent: UA
            referer: Referer header
            method: HTTP method
        """
        client = cls.get_client()
        if not client:
            return

        try:
            now = time.time()

            if not ip or not path:
                return

            # 1. سجل الـ request (timestamp + path)
            requests_key = cls._requests_key(ip)
            entry = f"{now}|{path}"
            await client.lpush(requests_key, entry)
            await client.ltrim(requests_key, 0, cls.MAX_REQUESTS_TRACKED - 1)
            await client.expire(requests_key, cls.WINDOW_TTL)

            # 2. سجل المسار الفريد (raw بدون query string)
            # ملاحظة: بنستخدم المسار الخام بدل normalized
            # عشان deep crawling detection يعرف يفرق
            # بين /product/1 و /product/2
            paths_key = cls._paths_key(ip)
            clean_path = path.split("?")[0]
            await client.sadd(paths_key, clean_path)
            await client.expire(paths_key, cls.WINDOW_TTL)

            # 3. إحصائيات
            stats_key = cls._stats_key(ip)
            pipe = client.pipeline()

            pipe.hincrby(stats_key, "total_requests", 1)

            if cls._is_static_asset(path):
                pipe.hincrby(stats_key, "static_requests", 1)
            else:
                pipe.hincrby(stats_key, "dynamic_requests", 1)

            if not referer:
                pipe.hincrby(stats_key, "no_referer_count", 1)

            if cls._is_suspicious_ua(user_agent):
                pipe.hincrby(stats_key, "suspicious_ua_count", 1)

            pipe.expire(stats_key, cls.WINDOW_TTL)
            await pipe.execute()

        except Exception as e:
            logger.error("scraping_record_failed", error=str(e))

    # ─── Detection: High Request Rate ─────────────────────

    @classmethod
    async def detect_high_request_rate(
        cls,
        ip: str,
        window_seconds: int = 60,
    ) -> Dict[str, Any]:
        """
        بيكشف معدل طلبات عالي.

        Args:
            ip: IP
            window_seconds: نافذة القياس (افتراضي دقيقة)
        """
        client = cls.get_client()
        if not client:
            return {"detected": False, "confidence": 0}

        try:
            requests_key = cls._requests_key(ip)
            entries = await client.lrange(requests_key, 0, -1)

            now = time.time()
            cutoff = now - window_seconds

            count = 0
            for entry in entries:
                try:
                    ts_str = entry.split("|", 1)[0]
                    if float(ts_str) > cutoff:
                        count += 1
                except (ValueError, IndexError):
                    continue

            # معدل في الدقيقة
            rate_per_min = count * (60 / window_seconds)

            if rate_per_min >= cls.VERY_HIGH_RATE:
                confidence = min(
                    cls.WEIGHTS["very_high_rate"]
                    + int((rate_per_min - cls.VERY_HIGH_RATE) / 20),
                    100,
                )
                return {
                    "detected": True,
                    "confidence": confidence,
                    "details": {
                        "rate_per_min": round(rate_per_min, 1),
                        "severity": "very_high",
                    },
                }

            if rate_per_min >= cls.HIGH_REQUEST_RATE:
                confidence = min(
                    cls.WEIGHTS["high_request_rate"]
                    + int((rate_per_min - cls.HIGH_REQUEST_RATE) / 10),
                    100,
                )
                return {
                    "detected": True,
                    "confidence": confidence,
                    "details": {
                        "rate_per_min": round(rate_per_min, 1),
                        "severity": "high",
                    },
                }

            return {"detected": False, "confidence": 0}

        except Exception as e:
            logger.error("scraping_rate_detect_failed", error=str(e))
            return {"detected": False, "confidence": 0}

    # ─── Detection: No Static Assets ──────────────────────

    @classmethod
    async def detect_no_static_assets(
        cls,
        ip: str,
        min_requests: int = 10,
    ) -> Dict[str, Any]:
        """
        بيكشف إن الـ IP مبيسحبش static assets.

        المستخدم الحقيقي بيطلب HTML + CSS + JS + صور.
        الـ scraper بيطلب HTML بس.
        """
        client = cls.get_client()
        if not client:
            return {"detected": False, "confidence": 0}

        try:
            stats_key = cls._stats_key(ip)
            stats = await client.hgetall(stats_key)

            if not stats:
                return {"detected": False, "confidence": 0}

            total = int(stats.get("total_requests", 0))
            static = int(stats.get("static_requests", 0))

            if total < min_requests:
                return {"detected": False, "confidence": 0}

            static_ratio = static / total

            if static_ratio < cls.STATIC_ASSET_MIN_RATIO:
                # كل ما قلّت النسبة، كل ما زادت الثقة
                deficit = cls.STATIC_ASSET_MIN_RATIO - static_ratio
                confidence = min(
                    cls.WEIGHTS["no_static_assets"] + int(deficit * 100),
                    100,
                )

                return {
                    "detected": True,
                    "confidence": confidence,
                    "details": {
                        "static_ratio": round(static_ratio, 3),
                        "total_requests": total,
                        "static_requests": static,
                    },
                }

            return {"detected": False, "confidence": 0}

        except Exception as e:
            logger.error("scraping_static_detect_failed", error=str(e))
            return {"detected": False, "confidence": 0}

    # ─── Detection: Deep Crawling ─────────────────────────

    @classmethod
    async def detect_deep_crawling(
        cls,
        ip: str,
    ) -> Dict[str, Any]:
        """بيكشف لو الـ IP زار مسارات كتير مختلفة."""
        client = cls.get_client()
        if not client:
            return {"detected": False, "confidence": 0}

        try:
            paths_key = cls._paths_key(ip)
            paths = await client.smembers(paths_key)

            count = len(paths)

            if count >= cls.DEEP_CRAWL_THRESHOLD:
                extra = min(count - cls.DEEP_CRAWL_THRESHOLD, 50)
                confidence = min(
                    cls.WEIGHTS["deep_crawling"] + (extra // 5),
                    100,
                )

                return {
                    "detected": True,
                    "confidence": confidence,
                    "details": {
                        "unique_paths": count,
                        "sample_paths": list(paths)[:5],
                    },
                }

            return {"detected": False, "confidence": 0}

        except Exception as e:
            logger.error("scraping_deep_detect_failed", error=str(e))
            return {"detected": False, "confidence": 0}

    # ─── Detection: Sequential Traversal ──────────────────

    @classmethod
    async def detect_sequential_traversal(
        cls,
        ip: str,
    ) -> Dict[str, Any]:
        """
        بيكشف الزيارة المتسلسلة.

        مثال: /product/1, /product/2, /product/3 ...
        """
        client = cls.get_client()
        if not client:
            return {"detected": False, "confidence": 0}

        try:
            requests_key = cls._requests_key(ip)
            entries = await client.lrange(requests_key, 0, 99)

            if len(entries) < cls.SEQUENTIAL_MIN_COUNT:
                return {"detected": False, "confidence": 0}

            # ترتيب زمني (الأقدم أولاً)
            entries = list(reversed(entries))

            ids = []
            for entry in entries:
                try:
                    _, path = entry.split("|", 1)
                    numeric_id = cls._extract_numeric_id(path)
                    if numeric_id is not None:
                        ids.append(numeric_id)
                except (ValueError, IndexError):
                    continue

            if len(ids) < cls.SEQUENTIAL_MIN_COUNT:
                return {"detected": False, "confidence": 0}

            # احسب عدد المرات اللي الـ IDs متتالية فيها
            sequential_count = 0
            for i in range(len(ids) - 1):
                diff = ids[i + 1] - ids[i]
                # +1 أو +2 أو -1 أو -2 → متسلسل
                if diff in (1, 2, -1, -2):
                    sequential_count += 1

            ratio = sequential_count / (len(ids) - 1)

            # لو 60%+ من الـ IDs متتالية → scraping
            if ratio >= 0.6 and sequential_count >= cls.SEQUENTIAL_MIN_COUNT:
                extra = int(ratio * 30)
                confidence = min(
                    cls.WEIGHTS["sequential_traversal"] + extra,
                    100,
                )

                logger.warning(
                    "scraping_sequential_traversal",
                    ip=ip,
                    sequential_count=sequential_count,
                    ratio=round(ratio, 2),
                )

                return {
                    "detected": True,
                    "confidence": confidence,
                    "details": {
                        "sequential_count": sequential_count,
                        "ratio": round(ratio, 2),
                        "sample_ids": ids[:10],
                    },
                }

            return {"detected": False, "confidence": 0}

        except Exception as e:
            logger.error("scraping_sequential_failed", error=str(e))
            return {"detected": False, "confidence": 0}

    # ─── Detection: Missing Referer ───────────────────────

    @classmethod
    async def detect_missing_referer(
        cls,
        ip: str,
        min_requests: int = 10,
    ) -> Dict[str, Any]:
        """
        بيكشف إن معظم الطلبات ملهاش referer.

        المستخدم الحقيقي بيجي من صفحات تانية.
        الـ scraper بيطلب كل صفحة مباشرة.
        """
        client = cls.get_client()
        if not client:
            return {"detected": False, "confidence": 0}

        try:
            stats_key = cls._stats_key(ip)
            stats = await client.hgetall(stats_key)

            if not stats:
                return {"detected": False, "confidence": 0}

            total = int(stats.get("total_requests", 0))
            no_ref = int(stats.get("no_referer_count", 0))

            if total < min_requests:
                return {"detected": False, "confidence": 0}

            ratio = no_ref / total

            # لو 80%+ من الطلبات بدون referer
            if ratio >= 0.8:
                return {
                    "detected": True,
                    "confidence": cls.WEIGHTS["missing_referer"],
                    "details": {
                        "no_referer_ratio": round(ratio, 3),
                        "total": total,
                        "no_referer": no_ref,
                    },
                }

            return {"detected": False, "confidence": 0}

        except Exception as e:
            logger.error("scraping_referer_failed", error=str(e))
            return {"detected": False, "confidence": 0}

    # ─── Detection: Uniform Timing ────────────────────────

    @classmethod
    async def detect_uniform_timing(
        cls,
        ip: str,
    ) -> Dict[str, Any]:
        """
        بيكشف التوقيت المنتظم.

        الـ bots بتطلب بفترات منتظمة.
        البشر عشوائيين.
        """
        client = cls.get_client()
        if not client:
            return {"detected": False, "confidence": 0}

        try:
            requests_key = cls._requests_key(ip)
            entries = await client.lrange(requests_key, 0, 49)

            if len(entries) < 10:
                return {"detected": False, "confidence": 0}

            timestamps = []
            for entry in entries:
                try:
                    ts_str = entry.split("|", 1)[0]
                    timestamps.append(float(ts_str))
                except (ValueError, IndexError):
                    continue

            if len(timestamps) < 10:
                return {"detected": False, "confidence": 0}

            timestamps.sort()

            intervals = [
                timestamps[i + 1] - timestamps[i]
                for i in range(len(timestamps) - 1)
            ]

            if not intervals:
                return {"detected": False, "confidence": 0}

            mean_interval = statistics.mean(intervals)

            if mean_interval <= 0:
                return {"detected": False, "confidence": 0}

            std_interval = (
                statistics.stdev(intervals)
                if len(intervals) > 1
                else 0.0
            )

            # Coefficient of Variation
            cv = std_interval / mean_interval

            if cv < cls.UNIFORM_TIMING_CV:
                confidence = min(
                    cls.WEIGHTS["uniform_timing"]
                    + int((cls.UNIFORM_TIMING_CV - cv) * 100),
                    100,
                )

                return {
                    "detected": True,
                    "confidence": confidence,
                    "details": {
                        "cv": round(cv, 4),
                        "mean_interval_sec": round(mean_interval, 3),
                        "std_interval_sec": round(std_interval, 3),
                    },
                }

            return {"detected": False, "confidence": 0}

        except Exception as e:
            logger.error("scraping_timing_failed", error=str(e))
            return {"detected": False, "confidence": 0}

    # ─── Detection: Suspicious UA ─────────────────────────

    @classmethod
    def detect_suspicious_user_agent(
        cls,
        user_agent: Optional[str],
    ) -> Dict[str, Any]:
        """بيكشف UA مشبوه."""
        if not user_agent:
            return {
                "detected": True,
                "confidence": cls.WEIGHTS["suspicious_user_agent"],
                "details": {"reason": "empty"},
            }

        ua_lower = user_agent.lower()

        # لو UA فيه اسم scraper صريح
        for fragment in ["scrapy", "mechanize", "phantomjs", "headlesschrome"]:
            if fragment in ua_lower:
                return {
                    "detected": True,
                    "confidence": cls.WEIGHTS["known_scraper_ua"],
                    "details": {
                        "reason": "known_scraper_ua",
                        "user_agent": user_agent[:120],
                    },
                }

        if cls._is_suspicious_ua(user_agent):
            return {
                "detected": True,
                "confidence": cls.WEIGHTS["suspicious_user_agent"],
                "details": {
                    "reason": "generic_bot_ua",
                    "user_agent": user_agent[:120],
                },
            }

        return {"detected": False, "confidence": 0}

    # ─── Main Detection ───────────────────────────────────

    @classmethod
    async def analyze_ip(
        cls,
        ip: str,
        user_agent: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        تحليل شامل لسلوك IP من منظور scraping.

        Returns:
            dict فيه:
            - is_scraping: bool
            - risk_score: 0-100
            - level: low/medium/high/critical
            - signals: list
            - details: تفاصيل
        """
        signals: List[str] = []
        details: Dict[str, Any] = {}
        total_score = 0

        # 1. High request rate
        rate = await cls.detect_high_request_rate(ip)
        if rate["detected"]:
            signals.append("high_request_rate")
            total_score += rate["confidence"]
            details["high_request_rate"] = rate["details"]

        # 2. No static assets
        static = await cls.detect_no_static_assets(ip)
        if static["detected"]:
            signals.append("no_static_assets")
            total_score += static["confidence"]
            details["no_static_assets"] = static["details"]

        # 3. Deep crawling
        deep = await cls.detect_deep_crawling(ip)
        if deep["detected"]:
            signals.append("deep_crawling")
            total_score += deep["confidence"]
            details["deep_crawling"] = deep["details"]

        # 4. Sequential traversal
        seq = await cls.detect_sequential_traversal(ip)
        if seq["detected"]:
            signals.append("sequential_traversal")
            total_score += seq["confidence"]
            details["sequential_traversal"] = seq["details"]

        # 5. Missing referer
        ref = await cls.detect_missing_referer(ip)
        if ref["detected"]:
            signals.append("missing_referer")
            total_score += ref["confidence"]
            details["missing_referer"] = ref["details"]

        # 6. Uniform timing
        timing = await cls.detect_uniform_timing(ip)
        if timing["detected"]:
            signals.append("uniform_timing")
            total_score += timing["confidence"]
            details["uniform_timing"] = timing["details"]

        # 7. Suspicious UA
        ua = cls.detect_suspicious_user_agent(user_agent)
        if ua["detected"]:
            signals.append("suspicious_user_agent")
            total_score += ua["confidence"]
            details["suspicious_user_agent"] = ua["details"]

        # 8. Risk Score
        risk_score = min(int(math.sqrt(total_score) * 10), 100)

        # 9. Level
        level = "clean"
        if risk_score >= cls.THRESHOLDS["critical"]:
            level = "critical"
        elif risk_score >= cls.THRESHOLDS["high"]:
            level = "high"
        elif risk_score >= cls.THRESHOLDS["medium"]:
            level = "medium"
        elif risk_score >= cls.THRESHOLDS["low"]:
            level = "low"

        # 10. Decision
        is_scraping = risk_score >= cls.THRESHOLDS["low"]

        if is_scraping:
            logger.warning(
                "scraping_detected",
                ip=ip,
                risk_score=risk_score,
                level=level,
                signals=signals,
            )

        return {
            "ip": ip,
            "is_scraping": is_scraping,
            "risk_score": risk_score,
            "level": level,
            "signals": signals,
            "signal_count": len(signals),
            "details": details,
        }

    # ─── Stats ─────────────────────────────────────────────

    @classmethod
    async def get_ip_stats(cls, ip: str) -> Dict[str, Any]:
        """بترجع إحصائيات IP."""
        client = cls.get_client()
        if not client:
            return {}

        try:
            stats_key = cls._stats_key(ip)
            paths_key = cls._paths_key(ip)
            requests_key = cls._requests_key(ip)

            stats = await client.hgetall(stats_key)
            unique_paths = await client.scard(paths_key)
            total_requests = await client.llen(requests_key)

            return {
                "ip": ip,
                "total_requests": total_requests,
                "unique_paths": unique_paths,
                "stats": stats,
            }

        except Exception as e:
            logger.error("scraping_get_stats_failed", error=str(e))
            return {}

    # ─── Utilities ─────────────────────────────────────────

    @classmethod
    async def clear_ip(cls, ip: str) -> None:
        """بيمسح بيانات IP."""
        client = cls.get_client()
        if not client:
            return

        try:
            keys = [
                cls._requests_key(ip),
                cls._paths_key(ip),
                cls._stats_key(ip),
            ]
            await client.delete(*keys)
            logger.info("scraping_ip_cleared", ip=ip)
        except Exception as e:
            logger.error("scraping_clear_ip_failed", error=str(e))

    @classmethod
    async def clear_all(cls) -> None:
        """بيمسح كل بيانات scraping."""
        client = cls.get_client()
        if not client:
            return

        try:
            cursor = 0
            while True:
                cursor, keys = await client.scan(
                    cursor=cursor,
                    match="scraping:*",
                    count=100,
                )
                if keys:
                    await client.delete(*keys)
                if cursor == 0:
                    break

            logger.info("scraping_all_cleared")
        except Exception as e:
            logger.error("scraping_clear_all_failed", error=str(e))

    @classmethod
    async def close(cls) -> None:
        """بتقفل Redis."""
        if cls._redis_client:
            await cls._redis_client.close()
            cls._redis_client = None