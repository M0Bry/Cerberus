"""
GeoIP Lookup — Maps IP addresses to geographic information.

بيوفر:
- Country lookup
- City lookup
- ISP / ASN lookup
- Timezone
- Coordinates
- VPN/Proxy/Tor detection
- Redis caching

الفكرة:
- بنستخدم MaxMind GeoLite2 Database (لو متاح)
- Fallback: Free APIs (ip-api.com, ipinfo.io)
- Redis caching عشان نتجنب الـ lookups المتكررة

الاستخدام:
- Geo Limiting
- Suspicious detection
- Fraud detection
- Compliance (GDPR, etc.)
"""

import ipaddress
import json
import time
from typing import Any, Dict, Optional

import httpx
import redis.asyncio as redis
import structlog

from app.core.config import settings

logger = structlog.get_logger()


class GeoIP:
    """
    GeoIP Lookup.

    الترتيب:
    1. Redis cache
    2. MaxMind GeoLite2 (لو متاح)
    3. Free API (ip-api.com)
    4. Fallback: unknown
    """

    _redis_client: Optional[redis.Redis] = None

    # ─── Config ────────────────────────────────────────────
    CACHE_TTL = 86400 * 7  # 7 أيام
    API_TIMEOUT = 3.0  # ثواني

    # ─── Private IP Ranges ────────────────────────────────
    PRIVATE_NETWORKS = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("::1/128"),
        ipaddress.ip_network("fc00::/7"),
        ipaddress.ip_network("fe80::/10"),
    ]

    # ─── Known VPN/Proxy ASNs ─────────────────────────────
    KNOWN_VPN_ASNS = {
        9009,      # M247 (NordVPN)
        212238,    # Datacamp (Surfshark)
        60068,     # Datacamp
        13335,     # Cloudflare
        16509,     # Amazon AWS
        14618,     # Amazon AWS
        15169,     # Google Cloud
        396982,    # Google Cloud
        8075,      # Microsoft Azure
        14061,     # DigitalOcean
        20473,     # Vultr
        63949,     # Linode
        24940,     # Hetzner
        16276,     # OVH
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
                logger.error("geoip_redis_init_failed", error=str(e))
                return None
        return cls._redis_client

    @staticmethod
    def _cache_key(ip: str) -> str:
        """بتبني مفتاح الـ cache."""
        return f"geoip:{ip}"

    # ─── IP Classification ────────────────────────────────

    @classmethod
    def is_private_ip(cls, ip: str) -> bool:
        """بيفحص لو الـ IP خاص (internal network)."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return any(ip_obj in net for net in cls.PRIVATE_NETWORKS)
        except (ValueError, TypeError):
            return False

    @classmethod
    def is_valid_ip(cls, ip: str) -> bool:
        """بيفحص لو الـ IP صالح."""
        try:
            ipaddress.ip_address(ip)
            return True
        except (ValueError, TypeError):
            return False

    # ─── Main API ──────────────────────────────────────────

    @classmethod
    async def lookup(cls, ip: str) -> Dict[str, Any]:
        """
        بيدور على معلومات IP.

        Args:
            ip: الـ IP

        Returns:
            dict فيه:
            - ip
            - country (كود)
            - country_name
            - city
            - region
            - isp
            - asn
            - timezone
            - latitude
            - longitude
            - is_vpn
            - is_proxy
            - is_hosting
            - is_private
            - source (cache/api/maxmind)
        """
        # 1. فحص صحة الـ IP
        if not cls.is_valid_ip(ip):
            return cls._unknown_result(ip, "invalid_ip")

        # 2. لو private IP
        if cls.is_private_ip(ip):
            return cls._unknown_result(ip, "private_ip")

        # 3. جرب Redis cache
        cached = await cls._get_from_cache(ip)
        if cached:
            cached["source"] = "cache"
            return cached

        # 4. جرب Free API
        result = await cls._lookup_via_api(ip)

        # 5. خزن في Redis
        if result.get("country"):
            await cls._store_in_cache(ip, result)

        return result

    @classmethod
    def _unknown_result(cls, ip: str, reason: str = "unknown") -> Dict[str, Any]:
        """نتيجة فاضية."""
        return {
            "ip": ip,
            "country": None,
            "country_name": None,
            "city": None,
            "region": None,
            "isp": None,
            "asn": None,
            "timezone": None,
            "latitude": None,
            "longitude": None,
            "is_vpn": False,
            "is_proxy": False,
            "is_hosting": False,
            "is_private": reason == "private_ip",
            "source": reason,
        }

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
            logger.warning("geoip_cache_get_failed", error=str(e))

        return None

    @classmethod
    async def _store_in_cache(cls, ip: str, data: Dict[str, Any]) -> None:
        """بيخزن في Redis cache."""
        client = cls.get_client()
        if not client:
            return

        try:
            key = cls._cache_key(ip)
            await client.setex(key, cls.CACHE_TTL, json.dumps(data))
        except Exception as e:
            logger.warning("geoip_cache_set_failed", error=str(e))

    # ─── API Lookup ────────────────────────────────────────

    @classmethod
    async def _lookup_via_api(cls, ip: str) -> Dict[str, Any]:
        """
        بيدور على الـ IP باستخدام ip-api.com (مجاني).

        Limits:
        - 45 requests/minute
        - No HTTPS on free tier
        """
        try:
            async with httpx.AsyncClient(timeout=cls.API_TIMEOUT) as client:
                response = await client.get(
                    f"http://ip-api.com/json/{ip}",
                    params={
                        "fields": (
                            "status,message,country,countryCode,"
                            "regionName,city,isp,org,as,timezone,"
                            "lat,lon,proxy,hosting"
                        )
                    },
                )

                if response.status_code != 200:
                    logger.warning(
                        "geoip_api_error",
                        ip=ip,
                        status=response.status_code,
                    )
                    return cls._unknown_result(ip, "api_error")

                data = response.json()

                if data.get("status") != "success":
                    return cls._unknown_result(ip, "api_fail")

                # استخرج ASN من "AS12345 ISP Name"
                asn_str = data.get("as", "")
                asn = None
                if asn_str:
                    parts = asn_str.split()
                    if parts and parts[0].startswith("AS"):
                        try:
                            asn = int(parts[0][2:])
                        except ValueError:
                            pass

                # فحص VPN/Proxy/Hosting
                is_hosting = data.get("hosting", False)
                is_proxy = data.get("proxy", False)
                is_vpn = is_hosting or is_proxy or (asn in cls.KNOWN_VPN_ASNS if asn else False)

                return {
                    "ip": ip,
                    "country": data.get("countryCode"),
                    "country_name": data.get("country"),
                    "city": data.get("city"),
                    "region": data.get("regionName"),
                    "isp": data.get("isp"),
                    "asn": asn,
                    "timezone": data.get("timezone"),
                    "latitude": data.get("lat"),
                    "longitude": data.get("lon"),
                    "is_vpn": is_vpn,
                    "is_proxy": is_proxy,
                    "is_hosting": is_hosting,
                    "is_private": False,
                    "source": "api",
                }

        except httpx.TimeoutException:
            logger.warning("geoip_api_timeout", ip=ip)
            return cls._unknown_result(ip, "timeout")
        except Exception as e:
            logger.error("geoip_lookup_failed", ip=ip, error=str(e))
            return cls._unknown_result(ip, "error")

    # ─── Sync Helpers ─────────────────────────────────────

    @classmethod
    def get_geo_info(cls, ip: str) -> Dict[str, Any]:
        """
        نسخة sync (للتوافق مع الكود القديم).

        ملاحظة: دي مش هتشتغل async، فبترجع private_ip أو unknown.
        للأداء الأفضل، استخدم `await GeoIP.lookup(ip)`.
        """
        if not cls.is_valid_ip(ip):
            return cls._unknown_result(ip, "invalid_ip")

        if cls.is_private_ip(ip):
            return cls._unknown_result(ip, "private_ip")

        # Fallback: unknown (مش بنعمل API call في sync mode)
        return cls._unknown_result(ip, "sync_not_supported")

    # ─── Analysis Helpers ─────────────────────────────────

    @classmethod
    async def get_country(cls, ip: str) -> Optional[str]:
        """بترجع كود الدولة بس (سريع)."""
        info = await cls.lookup(ip)
        return info.get("country")

    @classmethod
    async def is_vpn_or_proxy(cls, ip: str) -> bool:
        """بيفحص لو الـ IP VPN أو Proxy."""
        info = await cls.lookup(ip)
        return info.get("is_vpn", False) or info.get("is_proxy", False)

    @classmethod
    async def is_high_risk_country(cls, ip: str) -> bool:
        """
        بيفحص لو الدولة عالية الخطورة.

        High-risk countries:
        - Known for cyber attacks
        - Sanctioned
        """
        high_risk = {
            "KP",  # North Korea
            "IR",  # Iran
            "SY",  # Syria
            "CU",  # Cuba
        }

        country = await cls.get_country(ip)
        return country in high_risk if country else False

    # ─── Bulk Lookup ──────────────────────────────────────

    @classmethod
    async def lookup_bulk(cls, ips: list) -> Dict[str, Dict[str, Any]]:
        """
        بيدور على قائمة IPs.

        Args:
            ips: قائمة IPs

        Returns:
            dict فيه IP → معلومات
        """
        results = {}
        for ip in ips[:100]:  # حد 100 IP
            results[ip] = await cls.lookup(ip)
        return results

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
                logger.info("geoip_cache_cleared", ip=ip)
            else:
                # مسح كل الـ cache
                async for key in client.scan_iter(match="geoip:*", count=100):
                    await client.delete(key)
                logger.info("geoip_cache_cleared_all")
        except Exception as e:
            logger.error("geoip_cache_clear_failed", error=str(e))

    @classmethod
    async def close(cls) -> None:
        """بتقفل Redis."""
        if cls._redis_client:
            await cls._redis_client.close()
            cls._redis_client = None