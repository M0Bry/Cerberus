"""
Threat Intelligence — IP/ASN reputation & threat feed integration.

بيوفر:
- IP reputation checks (static + dynamic lists)
- Tor exit node detection
- Datacenter / cloud IP detection
- Known bad ASN detection
- Country/region blocking
- Custom threat feeds management
- Redis-backed caching
- Bulk check support
- Threat scoring

الفكرة:
- بنحمل قوائم threat intel (static + dynamic)
- بنخزنها في Redis
- كل IP جديد بنتحقق منه ضد القوائم
- بيدي reputation score سريع

المصادر المدعومة:
- Tor exit nodes (embedded + dynamic)
- Datacenter ranges (AWS, Azure, GCP, DigitalOcean)
- Known malicious ASNs
- Country blocks
- Custom IP/CIDR/ASN feeds

الاستخدام:
- defense_middleware.py
- abuse_detector.py
- ip_reputation.py
- anomaly_detection.py
- auto_mitigation.py
"""

import ipaddress
import json
import time
from typing import Any, Dict, List, Optional, Set, Tuple

import redis.asyncio as redis
import structlog

from app.core.config import settings

logger = structlog.get_logger()


class ThreatIntel:
    """
    Threat Intelligence Manager.

    الفكرة:
    - قوائم threat intel في Redis sets
    - فحص IP ضد القوائم
    - caching للنتائج
    """

    _redis_client: Optional[redis.Redis] = None

    # ─── Config ────────────────────────────────────────────
    CACHE_TTL = 3600             # ساعة للـ IP results
    FEED_TTL = 86400 * 7         # 7 أيام للـ feeds

    # ─── Redis Keys ───────────────────────────────────────
    TOR_EXITS_KEY = "ti:tor:exits"
    BAD_IPS_KEY = "ti:bad:ips"
    DATACENTER_CIDRS_KEY = "ti:datacenter:cidrs"
    BAD_ASNS_KEY = "ti:bad:asns"
    BLOCKED_COUNTRIES_KEY = "ti:blocked:countries"
    IP_CACHE_KEY_PREFIX = "ti:cache:ip:"

    # ─── Known Tor Exit Node Samples ──────────────────────
    # (embedded fallback — full list بيتحدث من dynamic feed)
    STATIC_TOR_EXITS: List[str] = [
        # عينة صغيرة للـ fallback
        # القائمة الكاملة بـ ~1000+ IP، بتتحدث من https://check.torproject.org/torbulkexitlist
    ]

    # ─── Known Datacenter CIDRs (Sample) ─────────────────
    STATIC_DATACENTER_CIDRS: List[str] = [
        # AWS
        "3.0.0.0/8",
        "52.0.0.0/8",
        "54.0.0.0/8",
        # Azure
        "13.64.0.0/11",
        "20.0.0.0/8",
        "40.64.0.0/10",
        # GCP
        "34.0.0.0/8",
        "35.0.0.0/8",
        # DigitalOcean
        "104.16.0.0/12",
        "159.65.0.0/16",
        "167.99.0.0/16",
        # Linode
        "45.33.0.0/16",
        "45.56.0.0/16",
        "45.79.0.0/16",
        # Vultr
        "45.32.0.0/16",
        "108.61.0.0/16",
        # Hetzner
        "5.9.0.0/16",
        "88.99.0.0/16",
    ]

    # ─── Known Bad ASNs (Sample) ──────────────────────────
    STATIC_BAD_ASNS: Set[int] = {
        # bulletproof hosting samples
        # تتحدث من dynamic feeds
    }

    # ─── Reputation Weights ───────────────────────────────
    WEIGHTS = {
        "tor_exit": 40,
        "known_bad_ip": 80,
        "datacenter": 20,
        "bad_asn": 50,
        "blocked_country": 60,
        "high_risk_country": 30,
    }

    # ─── High Risk Countries ──────────────────────────────
    HIGH_RISK_COUNTRIES: Set[str] = {
        # sample — حسب سياسة كل شركة
        "KP",  # North Korea
        # ممكن تضيف دول تانية حسب compliance
    }

    # ═══════════════════════════════════════════════════════
    #  Internal Helpers
    # ═══════════════════════════════════════════════════════

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
                logger.error("threat_intel_redis_init_failed", error=str(e))
                return None
        return cls._redis_client

    @staticmethod
    def _ip_cache_key(ip: str) -> str:
        return f"{ThreatIntel.IP_CACHE_KEY_PREFIX}{ip}"

    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """بيتحقق لو IP صحيح."""
        if not ip:
            return False
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    @staticmethod
    def _ip_in_cidr_list(
        ip: str,
        cidrs: List[str],
    ) -> Optional[str]:
        """بيتحقق لو الـ IP جوه أي CIDR."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for cidr in cidrs:
                try:
                    network = ipaddress.ip_network(cidr, strict=False)
                    if ip_obj in network:
                        return cidr
                except ValueError:
                    continue
        except ValueError:
            pass
        return None

    # ═══════════════════════════════════════════════════════
    #  Initialization
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def initialize(cls) -> Dict[str, Any]:
        """
        بيهيّئ الـ threat intel (يحمّل الـ static lists).

        Returns:
            dict فيه stats
        """
        client = cls.get_client()
        if not client:
            return {"success": False, "error": "redis_unavailable"}

        try:
            # 1. حمّل Tor exits
            if cls.STATIC_TOR_EXITS:
                await client.sadd(cls.TOR_EXITS_KEY, *cls.STATIC_TOR_EXITS)
                await client.expire(cls.TOR_EXITS_KEY, cls.FEED_TTL)

            # 2. حمّل datacenter CIDRs
            if cls.STATIC_DATACENTER_CIDRS:
                await client.sadd(
                    cls.DATACENTER_CIDRS_KEY,
                    *cls.STATIC_DATACENTER_CIDRS,
                )
                await client.expire(cls.DATACENTER_CIDRS_KEY, cls.FEED_TTL)

            # 3. حمّل bad ASNs
            if cls.STATIC_BAD_ASNS:
                await client.sadd(
                    cls.BAD_ASNS_KEY,
                    *[str(a) for a in cls.STATIC_BAD_ASNS],
                )
                await client.expire(cls.BAD_ASNS_KEY, cls.FEED_TTL)

            logger.info("threat_intel_initialized")

            return {
                "success": True,
                "tor_exits": len(cls.STATIC_TOR_EXITS),
                "datacenter_cidrs": len(cls.STATIC_DATACENTER_CIDRS),
                "bad_asns": len(cls.STATIC_BAD_ASNS),
            }

        except Exception as e:
            logger.error("threat_intel_init_failed", error=str(e))
            return {"success": False, "error": str(e)}

    # ═══════════════════════════════════════════════════════
    #  Feed Management
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def add_bad_ips(
        cls,
        ips: List[str],
        *,
        source: str = "custom",
    ) -> Dict[str, Any]:
        """
        بيضيف IPs للـ bad list.

        Args:
            ips: قائمة IPs
            source: المصدر (للتوثيق)

        Returns:
            dict فيه count
        """
        client = cls.get_client()
        if not client:
            return {"success": False, "error": "redis_unavailable"}

        try:
            valid_ips = [ip for ip in ips if cls._is_valid_ip(ip)]

            if not valid_ips:
                return {"success": False, "error": "no_valid_ips"}

            await client.sadd(cls.BAD_IPS_KEY, *valid_ips)
            await client.expire(cls.BAD_IPS_KEY, cls.FEED_TTL)

            logger.info(
                "threat_intel_bad_ips_added",
                count=len(valid_ips),
                source=source,
            )

            return {
                "success": True,
                "count": len(valid_ips),
                "source": source,
            }

        except Exception as e:
            logger.error("threat_intel_add_bad_ips_failed", error=str(e))
            return {"success": False, "error": str(e)}

    @classmethod
    async def add_tor_exits(
        cls,
        ips: List[str],
    ) -> Dict[str, Any]:
        """بيضيف Tor exit nodes."""
        client = cls.get_client()
        if not client:
            return {"success": False, "error": "redis_unavailable"}

        try:
            valid_ips = [ip for ip in ips if cls._is_valid_ip(ip)]

            if not valid_ips:
                return {"success": False, "error": "no_valid_ips"}

            await client.sadd(cls.TOR_EXITS_KEY, *valid_ips)
            await client.expire(cls.TOR_EXITS_KEY, cls.FEED_TTL)

            logger.info("threat_intel_tor_added", count=len(valid_ips))

            return {"success": True, "count": len(valid_ips)}

        except Exception as e:
            logger.error("threat_intel_add_tor_failed", error=str(e))
            return {"success": False, "error": str(e)}

    @classmethod
    async def add_datacenter_cidrs(
        cls,
        cidrs: List[str],
    ) -> Dict[str, Any]:
        """بيضيف datacenter CIDRs."""
        client = cls.get_client()
        if not client:
            return {"success": False, "error": "redis_unavailable"}

        try:
            valid_cidrs = []
            for cidr in cidrs:
                try:
                    ipaddress.ip_network(cidr, strict=False)
                    valid_cidrs.append(cidr)
                except ValueError:
                    continue

            if not valid_cidrs:
                return {"success": False, "error": "no_valid_cidrs"}

            await client.sadd(cls.DATACENTER_CIDRS_KEY, *valid_cidrs)
            await client.expire(cls.DATACENTER_CIDRS_KEY, cls.FEED_TTL)

            logger.info(
                "threat_intel_datacenter_added",
                count=len(valid_cidrs),
            )

            return {"success": True, "count": len(valid_cidrs)}

        except Exception as e:
            logger.error("threat_intel_add_datacenter_failed", error=str(e))
            return {"success": False, "error": str(e)}

    @classmethod
    async def add_bad_asns(
        cls,
        asns: List[int],
    ) -> Dict[str, Any]:
        """بيضيف bad ASNs."""
        client = cls.get_client()
        if not client:
            return {"success": False, "error": "redis_unavailable"}

        try:
            valid_asns = [str(a) for a in asns if isinstance(a, int) and a > 0]

            if not valid_asns:
                return {"success": False, "error": "no_valid_asns"}

            await client.sadd(cls.BAD_ASNS_KEY, *valid_asns)
            await client.expire(cls.BAD_ASNS_KEY, cls.FEED_TTL)

            logger.info("threat_intel_bad_asns_added", count=len(valid_asns))

            return {"success": True, "count": len(valid_asns)}

        except Exception as e:
            logger.error("threat_intel_add_bad_asns_failed", error=str(e))
            return {"success": False, "error": str(e)}

    @classmethod
    async def block_country(cls, country_code: str) -> Dict[str, Any]:
        """بيحظر دولة."""
        client = cls.get_client()
        if not client:
            return {"success": False, "error": "redis_unavailable"}

        try:
            cc = country_code.upper().strip()
            if not cc or len(cc) != 2:
                return {"success": False, "error": "invalid_country_code"}

            await client.sadd(cls.BLOCKED_COUNTRIES_KEY, cc)
            await client.expire(cls.BLOCKED_COUNTRIES_KEY, cls.FEED_TTL)

            logger.info("threat_intel_country_blocked", country=cc)

            return {"success": True, "country": cc}

        except Exception as e:
            logger.error("threat_intel_block_country_failed", error=str(e))
            return {"success": False, "error": str(e)}

    @classmethod
    async def unblock_country(cls, country_code: str) -> Dict[str, Any]:
        """بيرفع الحظر عن دولة."""
        client = cls.get_client()
        if not client:
            return {"success": False, "error": "redis_unavailable"}

        try:
            cc = country_code.upper().strip()
            await client.srem(cls.BLOCKED_COUNTRIES_KEY, cc)

            logger.info("threat_intel_country_unblocked", country=cc)

            return {"success": True, "country": cc}

        except Exception as e:
            logger.error("threat_intel_unblock_country_failed", error=str(e))
            return {"success": False, "error": str(e)}

    # ═══════════════════════════════════════════════════════
    #  IP Checks
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def check_ip(
        cls,
        ip: str,
        *,
        country: Optional[str] = None,
        asn: Optional[int] = None,
        use_cache: bool = True,
    ) -> Dict[str, Any]:
        """
        بيفحص IP ضد كل الـ threat intel lists.

        Args:
            ip: IP address
            country: كود الدولة (اختياري)
            asn: ASN number (اختياري)
            use_cache: يستخدم cache؟

        Returns:
            dict فيه:
            - is_threat: bool
            - threat_score: 0-100
            - level: clean/low/medium/high/critical
            - flags: list
            - details: تفاصيل
        """
        if not cls._is_valid_ip(ip):
            return {
                "success": False,
                "error": "invalid_ip",
                "is_threat": False,
                "threat_score": 0,
            }

        client = cls.get_client()
        if not client:
            return {
                "success": False,
                "error": "redis_unavailable",
                "is_threat": False,
                "threat_score": 0,
            }

        try:
            # ─── Check cache ───
            if use_cache:
                cache_key = cls._ip_cache_key(ip)
                cached = await client.get(cache_key)
                if cached:
                    try:
                        result = json.loads(cached)
                        result["from_cache"] = True
                        return result
                    except json.JSONDecodeError:
                        pass

            flags: List[str] = []
            details: Dict[str, Any] = {}
            total_score = 0

            # ─── 1. Tor exit node ───
            is_tor = await client.sismember(cls.TOR_EXITS_KEY, ip)
            if is_tor:
                flags.append("tor_exit")
                total_score += cls.WEIGHTS["tor_exit"]
                details["tor_exit"] = True

            # ─── 2. Known bad IP ───
            is_bad = await client.sismember(cls.BAD_IPS_KEY, ip)
            if is_bad:
                flags.append("known_bad_ip")
                total_score += cls.WEIGHTS["known_bad_ip"]
                details["known_bad_ip"] = True

            # ─── 3. Datacenter ───
            datacenter_cidrs = list(
                await client.smembers(cls.DATACENTER_CIDRS_KEY)
            )
            if datacenter_cidrs:
                matched_cidr = cls._ip_in_cidr_list(ip, datacenter_cidrs)
                if matched_cidr:
                    flags.append("datacenter")
                    total_score += cls.WEIGHTS["datacenter"]
                    details["datacenter_cidr"] = matched_cidr

            # ─── 4. Bad ASN ───
            if asn is not None:
                is_bad_asn = await client.sismember(
                    cls.BAD_ASNS_KEY, str(asn)
                )
                if is_bad_asn:
                    flags.append("bad_asn")
                    total_score += cls.WEIGHTS["bad_asn"]
                    details["asn"] = asn

            # ─── 5. Blocked country ───
            if country:
                cc = country.upper()
                is_blocked = await client.sismember(
                    cls.BLOCKED_COUNTRIES_KEY, cc
                )
                if is_blocked:
                    flags.append("blocked_country")
                    total_score += cls.WEIGHTS["blocked_country"]
                    details["country"] = cc

                elif cc in cls.HIGH_RISK_COUNTRIES:
                    flags.append("high_risk_country")
                    total_score += cls.WEIGHTS["high_risk_country"]
                    details["country"] = cc

            # ─── 6. Score & Level ───
            threat_score = min(total_score, 100)

            level = "clean"
            if threat_score >= 85:
                level = "critical"
            elif threat_score >= 70:
                level = "high"
            elif threat_score >= 50:
                level = "medium"
            elif threat_score >= 30:
                level = "low"

            is_threat = threat_score >= 30

            result = {
                "success": True,
                "ip": ip,
                "is_threat": is_threat,
                "threat_score": threat_score,
                "level": level,
                "flags": flags,
                "flag_count": len(flags),
                "details": details,
                "checked_at": time.time(),
                "from_cache": False,
            }

            # ─── Cache result ───
            if use_cache:
                cache_key = cls._ip_cache_key(ip)
                await client.set(
                    cache_key,
                    json.dumps(result),
                    ex=cls.CACHE_TTL,
                )

            if is_threat:
                logger.warning(
                    "threat_intel_threat_detected",
                    ip=ip,
                    threat_score=threat_score,
                    level=level,
                    flags=flags,
                )

            return result

        except Exception as e:
            logger.error("threat_intel_check_failed", error=str(e))
            return {
                "success": False,
                "error": str(e),
                "is_threat": False,
                "threat_score": 0,
            }

    @classmethod
    async def check_ips_bulk(
        cls,
        ips: List[str],
        *,
        use_cache: bool = True,
    ) -> Dict[str, Any]:
        """بيفحص مجموعة IPs مرة واحدة."""
        results: Dict[str, Dict[str, Any]] = {}
        threat_count = 0

        for ip in ips:
            result = await cls.check_ip(ip, use_cache=use_cache)
            results[ip] = result

            if result.get("is_threat"):
                threat_count += 1

        return {
            "success": True,
            "total": len(ips),
            "threats": threat_count,
            "clean": len(ips) - threat_count,
            "results": results,
        }

    @classmethod
    async def is_threat(
        cls,
        ip: str,
        threshold: int = 30,
    ) -> bool:
        """بيفحص سريع — بيرجع bool."""
        result = await cls.check_ip(ip)
        if not result.get("success"):
            return False
        return result.get("threat_score", 0) >= threshold

    # ═══════════════════════════════════════════════════════
    #  Stats
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def get_stats(cls) -> Dict[str, Any]:
        """بيرجع إحصائيات الـ threat intel."""
        client = cls.get_client()
        if not client:
            return {"success": False, "error": "redis_unavailable"}

        try:
            tor_count = await client.scard(cls.TOR_EXITS_KEY)
            bad_ips_count = await client.scard(cls.BAD_IPS_KEY)
            datacenter_count = await client.scard(cls.DATACENTER_CIDRS_KEY)
            bad_asns_count = await client.scard(cls.BAD_ASNS_KEY)
            blocked_countries_count = await client.scard(cls.BLOCKED_COUNTRIES_KEY)

            # عدد الـ cached IPs
            cache_count = 0
            cursor = 0
            while True:
                cursor, keys = await client.scan(
                    cursor=cursor,
                    match=f"{cls.IP_CACHE_KEY_PREFIX}*",
                    count=100,
                )
                cache_count += len(keys)
                if cursor == 0:
                    break

            return {
                "success": True,
                "tor_exits": tor_count,
                "bad_ips": bad_ips_count,
                "datacenter_cidrs": datacenter_count,
                "bad_asns": bad_asns_count,
                "blocked_countries": blocked_countries_count,
                "cached_ips": cache_count,
            }

        except Exception as e:
            logger.error("threat_intel_get_stats_failed", error=str(e))
            return {"success": False, "error": str(e)}

    # ═══════════════════════════════════════════════════════
    #  Utilities
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def clear_cache(cls) -> int:
        """بيمسح الـ IP cache."""
        client = cls.get_client()
        if not client:
            return 0

        try:
            count = 0
            cursor = 0
            while True:
                cursor, keys = await client.scan(
                    cursor=cursor,
                    match=f"{cls.IP_CACHE_KEY_PREFIX}*",
                    count=100,
                )
                if keys:
                    await client.delete(*keys)
                    count += len(keys)
                if cursor == 0:
                    break

            logger.info("threat_intel_cache_cleared", count=count)
            return count

        except Exception as e:
            logger.error("threat_intel_clear_cache_failed", error=str(e))
            return 0

    @classmethod
    async def clear_all(cls) -> None:
        """بيمسح كل بيانات الـ threat intel."""
        client = cls.get_client()
        if not client:
            return

        try:
            cursor = 0
            while True:
                cursor, keys = await client.scan(
                    cursor=cursor,
                    match="ti:*",
                    count=100,
                )
                if keys:
                    await client.delete(*keys)
                if cursor == 0:
                    break

            logger.info("threat_intel_all_cleared")
        except Exception as e:
            logger.error("threat_intel_clear_all_failed", error=str(e))

    @classmethod
    async def close(cls) -> None:
        """بتقفل Redis."""
        if cls._redis_client:
            await cls._redis_client.close()
            cls._redis_client = None


# ─── Standalone functions ─────────────────────────────

async def check_ip(
    ip: str,
    **kwargs,
) -> Dict[str, Any]:
    """Shortcut for ThreatIntel.check_ip."""
    return await ThreatIntel.check_ip(ip, **kwargs)


async def is_threat(ip: str, threshold: int = 30) -> bool:
    """Shortcut for ThreatIntel.is_threat."""
    return await ThreatIntel.is_threat(ip, threshold)


async def add_bad_ips(
    ips: List[str],
    source: str = "custom",
) -> Dict[str, Any]:
    """Shortcut for ThreatIntel.add_bad_ips."""
    return await ThreatIntel.add_bad_ips(ips, source=source)


async def block_country(country_code: str) -> Dict[str, Any]:
    """Shortcut for ThreatIntel.block_country."""
    return await ThreatIntel.block_country(country_code)