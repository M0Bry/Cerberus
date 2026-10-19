"""
VPN Detector — Detects VPN, Proxy, Tor, and Datacenter traffic.

بيوفر:
- VPN detection (ASN-based + behavior)
- Proxy detection (headers + ports)
- Tor detection (exit nodes list)
- Datacenter detection (hosting ASN)
- Confidence scoring
- Redis caching

الإشارات:
- ASN type (hosting/vpn)
- Proxy headers (X-Forwarded-For, Via)
- Port patterns
- Tor exit nodes
- IP behavior
- Geo mismatch

الاستخدام:
- منع abuse من VPNs
- Compliance (بعض الخدمات)
- Fraud detection
- Content restrictions
"""

import ipaddress
import json
import time
from typing import Any, Dict, List, Optional, Set

import redis.asyncio as redis
import structlog

from app.core.config import settings

logger = structlog.get_logger()


class VPNDetector:
    """
    VPN / Proxy / Tor Detector.

    الفكرة:
    - نجمع إشارات متعددة
    - كل إشارة ليها وزن
    - المجموع = confidence score
    """

    _redis_client: Optional[redis.Redis] = None

    # ─── Config ────────────────────────────────────────────
    CACHE_TTL = 86400  # 24 ساعة

    # ─── Weights ───────────────────────────────────────────
    WEIGHTS = {
        "vpn_asn": 50,            # ASN من نوع VPN
        "hosting_asn": 30,        # ASN من نوع hosting
        "proxy_headers": 25,      # Proxy headers
        "tor_exit": 90,           # Tor exit node
        "many_ips": 20,           # IP عنده IPs كتير
        "geo_mismatch": 15,       # Geo mismatch
        "suspicious_port": 20,    # Ports مشبوهة
        "fast_ip_change": 25,     # IP بيتغير بسرعة
    }

    # ─── Confidence Thresholds ────────────────────────────
    THRESHOLDS = {
        "low": 20,
        "medium": 40,
        "high": 60,
        "very_high": 80,
    }

    # ─── Proxy Headers ─────────────────────────────────────
    PROXY_HEADERS = [
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-real-ip",
        "via",
        "forwarded",
        "x-proxy-id",
        "proxy-connection",
        "x-proxy-authorization",
        "client-ip",
        "x-client-ip",
        "x-originating-ip",
        "x-remote-ip",
        "x-remote-addr",
        "x-cluster-client-ip",
        "true-client-ip",
    ]

    # ─── Suspicious Ports ──────────────────────────────────
    # ملاحظة: شلنا 443 و 80 لأنهم ports طبيعية (HTTPS/HTTP)
    SUSPICIOUS_PORTS = {
        9050,    # Tor default
        9051,    # Tor control
        9150,    # Tor Browser
        1080,    # SOCKS
        1081,    # SOCKS
        3128,    # Squid
        3129,    # Squid
        8080,    # HTTP Proxy (common)
        8118,    # Privoxy
        8888,    # HTTP Proxy
        10808,   # Shadowsocks
        10809,   # Shadowsocks
        8388,    # Shadowsocks
        7890,    # Clash HTTP Proxy
        7891,    # Clash SOCKS
        1087,    # V2Ray HTTP
        1086,    # V2Ray SOCKS
    }

    # ─── Known VPN ASNs (مكررة من ASNLookup) ──────────────
    KNOWN_VPN_ASNS = {
        9009,      # M247 (NordVPN)
        212238,    # Datacamp (Surfshark)
        60068,     # Datacamp
        39351,     # ExpressVPN
        51765,     # M247 UK
        202425,    # IPV6
    }

    # ─── Known Hosting ASNs ────────────────────────────────
    KNOWN_HOSTING_ASNS = {
        16509,     # Amazon AWS
        14618,     # Amazon AWS
        15169,     # Google
        396982,    # Google Cloud
        8075,      # Microsoft Azure
        14061,     # DigitalOcean
        20473,     # Vultr
        63949,     # Linode
        24940,     # Hetzner
        16276,     # OVH
        51167,     # Contabo
        197540,    # Netcup
        45090,     # Tencent
        37963,     # Alibaba
        55990,     # Huawei
    }

    # ─── Known Tor Exit Nodes (sample) ────────────────────
    # في الواقع، بتتحمل من https://check.torproject.org/torbulkexitlist
    KNOWN_TOR_EXITS: Set[str] = {
        "185.220.100.240",
        "185.220.100.241",
        "185.220.100.242",
        "185.220.100.243",
        "185.220.100.244",
        "185.220.100.245",
        "185.220.100.246",
        "185.220.100.247",
        "185.220.100.248",
        "185.220.100.249",
        "185.220.100.250",
        "185.220.100.251",
        "185.220.100.252",
        "185.220.100.253",
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
                logger.error("vpn_detector_redis_init_failed", error=str(e))
                return None
        return cls._redis_client

    @staticmethod
    def _cache_key(ip: str) -> str:
        """بتبني مفتاح الـ cache."""
        return f"vpn:{ip}"

    # ─── Tor Detection ────────────────────────────────────

    @classmethod
    def is_tor_exit(cls, ip: str) -> bool:
        """بيفحص لو الـ IP Tor exit node."""
        if ip in cls.KNOWN_TOR_EXITS:
            return True

        # فحص إضافي: Tor exit nodes غالباً من ASNs معينة
        return False

    @classmethod
    async def is_tor_exit_cached(cls, ip: str) -> bool:
        """بيفحص Tor مع Redis cache."""
        client = cls.get_client()
        if client:
            try:
                cached = await client.get(f"tor_exit:{ip}")
                if cached is not None:
                    return cached == "1"
            except Exception:
                pass

        # Fallback: local list
        is_tor = cls.is_tor_exit(ip)

        # خزن النتيجة
        if client:
            try:
                await client.setex(f"tor_exit:{ip}", 3600, "1" if is_tor else "0")
            except Exception:
                pass

        return is_tor

    # ─── Header Analysis ──────────────────────────────────

    @classmethod
    def detect_proxy_headers(cls, request) -> Dict[str, Any]:
        """
        بيدور على Proxy headers.

        Returns:
            dict فيه:
            - has_proxy_headers: bool
            - headers_found: list
            - score: int
        """
        headers_found = []

        for header in cls.PROXY_HEADERS:
            if request.headers.get(header):
                headers_found.append(header)

        # لو فيه أكتر من header → مشبوه
        score = 0
        if len(headers_found) >= 3:
            score = cls.WEIGHTS["proxy_headers"]
        elif len(headers_found) >= 1:
            score = cls.WEIGHTS["proxy_headers"] // 2

        return {
            "has_proxy_headers": len(headers_found) > 0,
            "headers_found": headers_found,
            "headers_count": len(headers_found),
            "score": score,
        }

    # ─── ASN Analysis ─────────────────────────────────────

    @classmethod
    async def detect_vpn_asn(cls, ip: str) -> Dict[str, Any]:
        """
        بيفحص الـ ASN للـ IP.

        Returns:
            dict فيه:
            - asn: رقم
            - type: vpn/hosting/isp/...
            - is_vpn: bool
            - is_hosting: bool
            - score: int
        """
        try:
            from app.core.geoip import GeoIP
            from app.core.asn_lookup import ASNLookup

            geo_info = await GeoIP.lookup(ip)
            asn = geo_info.get("asn")

            if not asn:
                return {
                    "asn": None,
                    "type": "unknown",
                    "is_vpn": False,
                    "is_hosting": False,
                    "score": 0,
                }

            asn_info = await ASNLookup.lookup(asn)
            asn_type = asn_info.get("type", "unknown")
            is_vpn = asn_type == "vpn"
            is_hosting = asn_type == "hosting"

            score = 0
            if is_vpn:
                score = cls.WEIGHTS["vpn_asn"]
            elif is_hosting:
                score = cls.WEIGHTS["hosting_asn"]

            return {
                "asn": asn,
                "asn_name": asn_info.get("name"),
                "type": asn_type,
                "is_vpn": is_vpn,
                "is_hosting": is_hosting,
                "score": score,
            }

        except Exception as e:
            logger.error("vpn_detector_asn_check_failed", ip=ip, error=str(e))
            return {
                "asn": None,
                "type": "unknown",
                "is_vpn": False,
                "is_hosting": False,
                "score": 0,
            }

    # ─── Port Analysis ────────────────────────────────────

    @classmethod
    def detect_suspicious_port(cls, port: Optional[int]) -> Dict[str, Any]:
        """بيفحص لو الـ port مشبوه."""
        if port is None:
            return {"port": None, "is_suspicious": False, "score": 0}

        is_suspicious = port in cls.SUSPICIOUS_PORTS

        return {
            "port": port,
            "is_suspicious": is_suspicious,
            "score": cls.WEIGHTS["suspicious_port"] if is_suspicious else 0,
        }

    # ─── Geo Mismatch ─────────────────────────────────────

    @classmethod
    async def detect_geo_mismatch(
        cls,
        ip: str,
        request,
    ) -> Dict[str, Any]:
        """
        بيفحص لو فيه Geo mismatch.

        مثال: IP من US بس الـ Accept-Language عربي.
        """
        try:
            from app.core.geoip import GeoIP

            geo = await GeoIP.lookup(ip)
            country = geo.get("country")

            if not country:
                return {"has_mismatch": False, "score": 0}

            # فحص Accept-Language
            accept_lang = request.headers.get("accept-language", "").lower()

            # فحص TIMEZONE header (لو موجود)
            client_timezone = request.headers.get("x-timezone", "").lower()

            # قواعد بسيطة
            mismatch = False
            reasons = []

            # لو IP من EG بس الـ accept-language مفيش فيه ar
            if country == "EG" and accept_lang and "ar" not in accept_lang:
                mismatch = True
                reasons.append(f"country=EG but accept-language={accept_lang[:20]}")

            # لو IP من US بس الـ accept-language فيه ar
            if country == "US" and "ar" in accept_lang:
                # ده عادي لو المستخدم عربي
                pass

            return {
                "has_mismatch": mismatch,
                "country": country,
                "accept_language": accept_lang[:50],
                "reasons": reasons,
                "score": cls.WEIGHTS["geo_mismatch"] if mismatch else 0,
            }

        except Exception as e:
            logger.error("vpn_detector_geo_mismatch_failed", error=str(e))
            return {"has_mismatch": False, "score": 0}

    # ─── Main Detection ────────────────────────────────────

    @classmethod
    async def detect(
        cls,
        ip: str,
        request=None,
        skip_cache: bool = False,
    ) -> Dict[str, Any]:
        """
        بيكشف لو الـ IP من VPN/Proxy/Tor.

        Args:
            ip: الـ IP
            request: FastAPI Request (اختياري - للـ headers)
            skip_cache: تجاهل الـ cache

        Returns:
            dict فيه:
            - is_vpn: bool
            - is_proxy: bool
            - is_tor: bool
            - is_hosting: bool
            - confidence: 0-100
            - level: low/medium/high/very_high
            - signals: list of detected signals
            - details: تفاصيل كل signal
        """
        # 1. فحص الـ cache
        if not skip_cache:
            cached = await cls._get_from_cache(ip)
            if cached:
                cached["source"] = "cache"
                return cached

        # 2. جمع الإشارات
        signals: List[str] = []
        details: Dict[str, Any] = {}
        total_score = 0

        # 2a. Tor exit check
        is_tor = await cls.is_tor_exit_cached(ip)
        if is_tor:
            signals.append("tor_exit")
            details["tor"] = {"is_tor": True, "score": cls.WEIGHTS["tor_exit"]}
            total_score += cls.WEIGHTS["tor_exit"]

        # 2b. ASN check
        asn_result = await cls.detect_vpn_asn(ip)
        details["asn"] = asn_result
        total_score += asn_result["score"]

        is_vpn = asn_result["is_vpn"]
        is_hosting = asn_result["is_hosting"]

        if is_vpn:
            signals.append("vpn_asn")
        if is_hosting:
            signals.append("hosting_asn")

        # 2c. Header check (لو فيه request)
        is_proxy_headers = False
        if request:
            header_result = cls.detect_proxy_headers(request)
            details["headers"] = header_result
            if header_result["has_proxy_headers"]:
                is_proxy_headers = True
                signals.append("proxy_headers")
                total_score += header_result["score"]

            # 2d. Geo mismatch
            geo_result = await cls.detect_geo_mismatch(ip, request)
            details["geo"] = geo_result
            if geo_result["has_mismatch"]:
                signals.append("geo_mismatch")
                total_score += geo_result["score"]

        # 3. احسب الـ confidence
        confidence = min(total_score, 100)

        # 4. حدد الـ level
        level = "clean"
        if confidence >= cls.THRESHOLDS["very_high"]:
            level = "very_high"
        elif confidence >= cls.THRESHOLDS["high"]:
            level = "high"
        elif confidence >= cls.THRESHOLDS["medium"]:
            level = "medium"
        elif confidence >= cls.THRESHOLDS["low"]:
            level = "low"

        # 5. القرار النهائي
        is_proxy = is_proxy_headers
        is_vpn_total = is_vpn or is_tor or (is_hosting and confidence >= 30)

        result = {
            "ip": ip,
            "is_vpn": is_vpn_total,
            "is_proxy": is_proxy,
            "is_tor": is_tor,
            "is_hosting": is_hosting,
            "confidence": confidence,
            "level": level,
            "signals": signals,
            "details": details,
            "source": "analysis",
        }

        # 6. خزن في cache
        await cls._store_in_cache(ip, result)

        if confidence >= cls.THRESHOLDS["medium"]:
            logger.warning(
                "vpn_detected",
                ip=ip,
                confidence=confidence,
                level=level,
                signals=signals,
            )

        return result

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
            logger.warning("vpn_cache_get_failed", error=str(e))

        return None

    @classmethod
    async def _store_in_cache(cls, ip: str, data: Dict[str, Any]) -> None:
        """بيخزن في Redis cache."""
        client = cls.get_client()
        if not client:
            return

        try:
            key = cls._cache_key(ip)
            # نخزن بدون details (عشان حجم الـ cache)
            cache_data = {k: v for k, v in data.items() if k != "details"}
            await client.setex(key, cls.CACHE_TTL, json.dumps(cache_data))
        except Exception as e:
            logger.warning("vpn_cache_set_failed", error=str(e))

    # ─── Tor Exit List Management ─────────────────────────

    @classmethod
    async def update_tor_exit_list(cls) -> int:
        """
        بيحدّث قائمة Tor exit nodes من Tor Project.

        Returns:
            عدد الـ nodes اللي اتحدثت
        """
        try:
            import httpx

            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    "https://check.torproject.org/torbulkexitlist",
                )

                if response.status_code != 200:
                    logger.warning(
                        "tor_exit_list_fetch_failed",
                        status=response.status_code,
                    )
                    return 0

                # فكك الـ response
                lines = response.text.strip().split("\n")
                exit_ips = set()

                for line in lines:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        ipaddress.ip_address(line)
                        exit_ips.add(line)
                    except ValueError:
                        continue

                # خزن في Redis
                redis_client = cls.get_client()
                if redis_client:
                    key = "tor_exit_nodes"
                    await redis_client.delete(key)
                    if exit_ips:
                        await redis_client.sadd(key, *exit_ips)
                        await redis_client.expire(key, 86400)  # 24 ساعة

                # حدّث الـ local set
                cls.KNOWN_TOR_EXITS = exit_ips

                logger.info(
                    "tor_exit_list_updated",
                    count=len(exit_ips),
                )
                return len(exit_ips)

        except Exception as e:
            logger.error("tor_exit_list_update_failed", error=str(e))
            return 0

    # ─── Utilities ─────────────────────────────────────────

    @classmethod
    async def get_summary(cls, ip: str) -> Dict[str, Any]:
        """بترجع ملخص سريع."""
        result = await cls.detect(ip)
        return {
            "ip": ip,
            "is_vpn": result["is_vpn"],
            "is_tor": result["is_tor"],
            "is_hosting": result["is_hosting"],
            "confidence": result["confidence"],
            "level": result["level"],
        }

    @classmethod
    async def clear_cache(cls, ip: Optional[str] = None) -> None:
        """بيمسح cache."""
        client = cls.get_client()
        if not client:
            return

        try:
            if ip:
                await client.delete(cls._cache_key(ip))
                logger.info("vpn_cache_cleared", ip=ip)
            else:
                async for key in client.scan_iter(match="vpn:*", count=100):
                    await client.delete(key)
                logger.info("vpn_cache_cleared_all")
        except Exception as e:
            logger.error("vpn_cache_clear_failed", error=str(e))

    @classmethod
    async def close(cls) -> None:
        """بتقفل Redis."""
        if cls._redis_client:
            await cls._redis_client.close()
            cls._redis_client = None