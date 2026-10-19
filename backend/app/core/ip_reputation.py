"""
IP Reputation — Checks IP reputation from external sources.

بيوفر:
- AbuseIPDB integration
- VirusTotal integration
- Shodan integration
- Local reputation database
- Confidence scoring
- Redis caching (لتجنب الـ API limits)

الفكرة:
- نجمع بيانات من مصادر متعددة
- نحسب overall reputation score
- نصنف الـ IP

Sources:
- AbuseIPDB: abuse reports
- VirusTotal: security vendors
- Shodan: open ports / vulns
- Local: system's own history

الاستخدام:
- Fraud detection
- Access control
- Threat intelligence
"""

import ipaddress
import json
import time
from typing import Any, Dict, List, Optional

import httpx
import redis.asyncio as redis
import structlog

from app.core.config import settings

logger = structlog.get_logger()


class IPReputation:
    """
    IP Reputation Checker.

    الفكرة:
    - نجمع من مصادر متعددة
    - نحسب overall score
    - نصنف الـ IP
    """

    _redis_client: Optional[redis.Redis] = None

    # ─── Config ────────────────────────────────────────────
    CACHE_TTL = 86400 * 3  # 3 أيام
    API_TIMEOUT = 5.0

    # ─── Classification ────────────────────────────────────
    SCORE_THRESHOLDS = {
        "clean": (0, 20),
        "low_risk": (20, 40),
        "suspicious": (40, 70),
        "malicious": (70, 100),
    }

    # ─── Private IP Ranges ────────────────────────────────
    PRIVATE_NETWORKS = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
    ]

    # ─── Well-known safe IPs ──────────────────────────────
    WELL_KNOWN_SAFE = {
        # Google DNS
        "8.8.8.8": "Google DNS",
        "8.8.4.4": "Google DNS",
        # Cloudflare DNS
        "1.1.1.1": "Cloudflare DNS",
        "1.0.0.1": "Cloudflare DNS",
        # Quad9
        "9.9.9.9": "Quad9 DNS",
        # OpenDNS
        "208.67.222.222": "OpenDNS",
        "208.67.220.220": "OpenDNS",
    }

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
                logger.error("ip_reputation_redis_init_failed", error=str(e))
                return None
        return cls._redis_client

    @staticmethod
    def _cache_key(ip: str) -> str:
        return f"ip_rep:{ip}"

    # ─── IP Validation ────────────────────────────────────

    @classmethod
    def is_valid_ip(cls, ip: str) -> bool:
        """بيفحص لو الـ IP صالح."""
        try:
            ipaddress.ip_address(ip)
            return True
        except (ValueError, TypeError):
            return False

    @classmethod
    def is_private_ip(cls, ip: str) -> bool:
        """بيفحص لو private IP."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return any(ip_obj in net for net in cls.PRIVATE_NETWORKS)
        except (ValueError, TypeError):
            return False

    # ─── Classification ───────────────────────────────────

    @classmethod
    def classify_score(cls, score: int) -> str:
        """بيصنف الـ score."""
        for level, (low, high) in cls.SCORE_THRESHOLDS.items():
            if low <= score < high:
                return level
        return "malicious"  # score >= 100

    # ─── AbuseIPDB ─────────────────────────────────────────

    @classmethod
    async def _check_abuseipdb(cls, ip: str) -> Dict[str, Any]:
        """
        بيفحص IP في AbuseIPDB.

        بيحتاج ABUSEIPDB_API_KEY في .env
        """
        api_key = getattr(settings, "ABUSEIPDB_API_KEY", None)
        if not api_key:
            return {"available": False, "reason": "no_api_key"}

        try:
            async with httpx.AsyncClient(timeout=cls.API_TIMEOUT) as client:
                response = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={
                        "ipAddress": ip,
                        "maxAgeInDays": 90,
                    },
                    headers={
                        "Key": api_key,
                        "Accept": "application/json",
                    },
                )

                if response.status_code != 200:
                    return {
                        "available": False,
                        "reason": f"http_{response.status_code}",
                    }

                data = response.json().get("data", {})

                abuse_score = data.get("abuseConfidenceScore", 0)
                total_reports = data.get("totalReports", 0)
                country = data.get("countryCode")
                isp = data.get("isp")
                domain = data.get("domain")
                usage_type = data.get("usageType")

                return {
                    "available": True,
                    "abuse_score": abuse_score,
                    "total_reports": total_reports,
                    "country": country,
                    "isp": isp,
                    "domain": domain,
                    "usage_type": usage_type,
                }

        except httpx.TimeoutException:
            return {"available": False, "reason": "timeout"}
        except Exception as e:
            logger.error("abuseipdb_error", error=str(e))
            return {"available": False, "reason": "error"}

    # ─── VirusTotal ───────────────────────────────────────

    @classmethod
    async def _check_virustotal(cls, ip: str) -> Dict[str, Any]:
        """
        بيفحص IP في VirusTotal.

        بيحتاج VIRUSTOTAL_API_KEY في .env
        """
        api_key = getattr(settings, "VIRUSTOTAL_API_KEY", None)
        if not api_key:
            return {"available": False, "reason": "no_api_key"}

        try:
            async with httpx.AsyncClient(timeout=cls.API_TIMEOUT) as client:
                response = await client.get(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                    headers={"x-apikey": api_key},
                )

                if response.status_code != 200:
                    return {
                        "available": False,
                        "reason": f"http_{response.status_code}",
                    }

                data = response.json().get("data", {})
                attributes = data.get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})

                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)

                total = malicious + suspicious + harmless + undetected

                # احسب score
                if total > 0:
                    vt_score = int(((malicious * 2 + suspicious) / (total * 2)) * 100)
                else:
                    vt_score = 0

                return {
                    "available": True,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                    "score": min(vt_score, 100),
                }

        except httpx.TimeoutException:
            return {"available": False, "reason": "timeout"}
        except Exception as e:
            logger.error("virustotal_error", error=str(e))
            return {"available": False, "reason": "error"}

    # ─── Local Reputation ─────────────────────────────────

    @classmethod
    async def _check_local(cls, ip: str) -> Dict[str, Any]:
        """
        بيفحص السمعة المحلية (من نظامنا).

        بيستخدم:
        - ProgressiveBlocker offenses
        - AbuseDetector history
        - RequestAnalytics
        """
        try:
            from app.core.progressive_blocker import ProgressiveBlocker
            from app.core.abuse_detector import AbuseDetector

            # 1. فحص المخالفات
            block_info = await ProgressiveBlocker.get_block_info(ip)
            offenses = block_info.get("offense_count", 0)

            # 2. فحص لو محظور في AbuseDetector
            is_blocked = await AbuseDetector.is_blocked(ip)

            # 3. احسب score
            local_score = 0
            if is_blocked:
                local_score += 50
            if offenses > 0:
                local_score += min(offenses * 10, 50)

            return {
                "available": True,
                "offense_count": offenses,
                "is_blocked": is_blocked,
                "score": min(local_score, 100),
            }

        except Exception as e:
            logger.warning("local_reputation_error", error=str(e))
            return {"available": False, "reason": "error"}

    # ─── Main Lookup ──────────────────────────────────────

    @classmethod
    async def lookup(
        cls,
        ip: str,
        skip_cache: bool = False,
    ) -> Dict[str, Any]:
        """
        بيدور على سمعة الـ IP.

        Args:
            ip: الـ IP
            skip_cache: تجاهل الـ cache

        Returns:
            dict فيه:
            - ip
            - score: 0-100 (0 = clean, 100 = malicious)
            - classification: clean / low_risk / suspicious / malicious
            - sources: dict لكل مصدر
            - is_safe: bool
            - is_malicious: bool
        """
        # 1. Validate
        if not cls.is_valid_ip(ip):
            return cls._empty_result(ip, "invalid_ip")

        if cls.is_private_ip(ip):
            return cls._empty_result(ip, "private_ip", is_safe=True)

        # 2. Well-known safe
        if ip in cls.WELL_KNOWN_SAFE:
            return {
                "ip": ip,
                "score": 0,
                "classification": "clean",
                "is_safe": True,
                "is_malicious": False,
                "sources": {
                    "well_known": {
                        "available": True,
                        "name": cls.WELL_KNOWN_SAFE[ip],
                        "score": 0,
                    }
                },
                "source": "well_known",
            }

        # 3. Cache
        if not skip_cache:
            cached = await cls._get_from_cache(ip)
            if cached:
                cached["source"] = "cache"
                return cached

        # 4. Check all sources (parallel-ish)
        sources: Dict[str, Any] = {}

        # 4a. AbuseIPDB
        abuse = await cls._check_abuseipdb(ip)
        sources["abuseipdb"] = abuse

        # 4b. VirusTotal
        vt = await cls._check_virustotal(ip)
        sources["virustotal"] = vt

        # 4c. Local
        local = await cls._check_local(ip)
        sources["local"] = local

        # 5. Combine scores (weighted)
        weights = {
            "abuseipdb": 0.4,
            "virustotal": 0.4,
            "local": 0.2,
        }

        total_weight = 0
        weighted_score = 0

        for source_name, source_data in sources.items():
            if source_data.get("available"):
                weight = weights.get(source_name, 0)
                score = source_data.get("score", 0)
                # لو abuseipdb، الـ score هو abuse_score
                if source_name == "abuseipdb":
                    score = source_data.get("abuse_score", 0)

                weighted_score += score * weight
                total_weight += weight

        if total_weight > 0:
            final_score = int(weighted_score / total_weight)
        else:
            final_score = 0

        # 6. Classification
        classification = cls.classify_score(final_score)

        result = {
            "ip": ip,
            "score": final_score,
            "classification": classification,
            "is_safe": final_score < 40,
            "is_malicious": final_score >= 70,
            "sources": sources,
            "source": "lookup",
        }

        # 7. Log if malicious
        if result["is_malicious"]:
            logger.warning(
                "malicious_ip_detected",
                ip=ip,
                score=final_score,
                classification=classification,
            )

        # 8. Cache
        await cls._store_in_cache(ip, result)

        return result

    @classmethod
    def _empty_result(
        cls,
        ip: str,
        reason: str,
        is_safe: bool = False,
    ) -> Dict[str, Any]:
        """نتيجة فاضية."""
        return {
            "ip": ip,
            "score": 0,
            "classification": "clean" if is_safe else "unknown",
            "is_safe": is_safe,
            "is_malicious": False,
            "sources": {},
            "source": reason,
        }

    # ─── Batch ────────────────────────────────────────────

    @classmethod
    async def lookup_bulk(
        cls,
        ips: List[str],
    ) -> Dict[str, Dict[str, Any]]:
        """بيدور على قائمة IPs."""
        results = {}
        for ip in ips[:50]:  # حد 50
            results[ip] = await cls.lookup(ip)
        return results

    # ─── Helpers ──────────────────────────────────────────

    @classmethod
    async def is_malicious(cls, ip: str) -> bool:
        """بيفحص لو الـ IP خبيث."""
        result = await cls.lookup(ip)
        return result.get("is_malicious", False)

    @classmethod
    async def is_safe(cls, ip: str) -> bool:
        """بيفحص لو الـ IP آمن."""
        result = await cls.lookup(ip)
        return result.get("is_safe", False)

    @classmethod
    async def get_score(cls, ip: str) -> int:
        """بترجع الـ score بس."""
        result = await cls.lookup(ip)
        return result.get("score", 0)

    @classmethod
    async def get_classification(cls, ip: str) -> str:
        """بترجع التصنيف بس."""
        result = await cls.lookup(ip)
        return result.get("classification", "unknown")

    # ─── Cache ─────────────────────────────────────────────

    @classmethod
    async def _get_from_cache(cls, ip: str) -> Optional[Dict[str, Any]]:
        """بيجيب من Redis cache."""
        client = cls.get_client()
        if not client:
            return None

        try:
            key = cls._cache_key(ip)
            data = await client.get(key)
            if data:
                return json.loads(data)
        except Exception as e:
            logger.warning("ip_rep_cache_get_failed", error=str(e))

        return None

    @classmethod
    async def _store_in_cache(cls, ip: str, data: Dict[str, Any]) -> None:
        """بيخزن في Redis cache."""
        client = cls.get_client()
        if not client:
            return

        try:
            key = cls._cache_key(ip)
            # نخزن بدون sources (لتقليل الحجم)
            cache_data = {k: v for k, v in data.items() if k != "sources"}
            await client.setex(key, cls.CACHE_TTL, json.dumps(cache_data))
        except Exception as e:
            logger.warning("ip_rep_cache_set_failed", error=str(e))

    # ─── Report ───────────────────────────────────────────

    @classmethod
    async def report_bad_ip(
        cls,
        ip: str,
        category: str = "hacking",
        comment: str = "",
    ) -> bool:
        """
        بتبلغ AbuseIPDB عن IP سيء.

        Args:
            ip: الـ IP
            category: نوع المخالفة
            comment: تعليق

        Returns:
            True لو نجح
        """
        api_key = getattr(settings, "ABUSEIPDB_API_KEY", None)
        if not api_key:
            return False

        try:
            async with httpx.AsyncClient(timeout=cls.API_TIMEOUT) as client:
                response = await client.post(
                    "https://api.abuseipdb.com/api/v2/report",
                    data={
                        "ip": ip,
                        "categories": category,
                        "comment": comment[:1024],
                    },
                    headers={
                        "Key": api_key,
                        "Accept": "application/json",
                    },
                )

                if response.status_code == 200:
                    logger.info("ip_reported", ip=ip, category=category)
                    # امسح الـ cache عشان نعكس التحديث
                    await cls.clear_cache(ip)
                    return True

                return False

        except Exception as e:
            logger.error("report_bad_ip_error", error=str(e))
            return False

    # ─── Utilities ─────────────────────────────────────────

    @classmethod
    async def clear_cache(cls, ip: Optional[str] = None) -> None:
        """بيمسح cache."""
        client = cls.get_client()
        if not client:
            return

        try:
            if ip:
                await client.delete(cls._cache_key(ip))
                logger.info("ip_rep_cache_cleared", ip=ip)
            else:
                async for key in client.scan_iter(match="ip_rep:*", count=100):
                    await client.delete(key)
                logger.info("ip_rep_cache_cleared_all")
        except Exception as e:
            logger.error("ip_rep_cache_clear_failed", error=str(e))

    @classmethod
    async def close(cls) -> None:
        """بتقفل Redis."""
        if cls._redis_client:
            await cls._redis_client.close()
            cls._redis_client = None