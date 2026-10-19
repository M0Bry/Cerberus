"""
ASN Lookup — Maps IPs to Autonomous System Numbers.

بيوفر:
- ASN lookup from IP
- AS classification (hosting, isp, education, government, business)
- Known ASN database (VPNs, Cloud providers, ISPs)
- Redis caching
- Fast lookups

الفكرة:
- كل IP بينتمي لـ AS (Autonomous System)
- الـ AS ليها رقم فريد (ASN)
- كل ASN له تصنيف

الاستخدام:
- كشف الـ Datacenter traffic
- تحليل مصادر الهجمات
- Fraud detection
- VPN/Proxy detection
"""

import ipaddress
import json
import re
from typing import Any, Dict, Optional, Set

import redis.asyncio as redis
import structlog

from app.core.config import settings

logger = structlog.get_logger()


class ASNLookup:
    """
    ASN Lookup.

    الفكرة:
    1. نحدد الـ ASN من الـ IP
    2. نصنف الـ ASN
    3. نخزن في Redis
    """

    _redis_client: Optional[redis.Redis] = None

    # ─── Config ────────────────────────────────────────────
    CACHE_TTL = 86400 * 7  # 7 أيام

    # ─── AS Types ──────────────────────────────────────────
    AS_TYPES = {
        "hosting",     # Datacenters, Cloud
        "isp",         # Internet Service Providers
        "education",   # Universities
        "government",  # Government agencies
        "business",    # Companies
        "cdn",         # Content Delivery Networks
        "vpn",         # VPN providers
        "unknown",
    }

    # ─── Known ASN Database ───────────────────────────────
    # (رقم ASN: {name, description, type, country})
    KNOWN_ASNS: Dict[int, Dict[str, Any]] = {
        # ─── Cloud Providers (hosting) ───
        16509: {"name": "AMAZON-02", "description": "Amazon AWS", "type": "hosting", "country": "US"},
        14618: {"name": "AMAZON-AES", "description": "Amazon AWS", "type": "hosting", "country": "US"},
        15169: {"name": "GOOGLE", "description": "Google LLC", "type": "hosting", "country": "US"},
        396982: {"name": "GOOGLE-CLOUD", "description": "Google Cloud", "type": "hosting", "country": "US"},
        8075: {"name": "MICROSOFT", "description": "Microsoft Azure", "type": "hosting", "country": "US"},
        8068: {"name": "MICROSOFT", "description": "Microsoft Azure", "type": "hosting", "country": "US"},
        14061: {"name": "DIGITALOCEAN", "description": "DigitalOcean", "type": "hosting", "country": "US"},
        20473: {"name": "AS-CHOOPA", "description": "Vultr", "type": "hosting", "country": "US"},
        63949: {"name": "LINODE", "description": "Linode", "type": "hosting", "country": "US"},
        24940: {"name": "HETZNER", "description": "Hetzner Online", "type": "hosting", "country": "DE"},
        16276: {"name": "OVH", "description": "OVH SAS", "type": "hosting", "country": "FR"},
        12876: {"name": "ONLINE-NET", "description": "Online SAS", "type": "hosting", "country": "FR"},
        51167: {"name": "CONTABO", "description": "Contabo GmbH", "type": "hosting", "country": "DE"},
        197540: {"name": "NETCUP", "description": "Netcup GmbH", "type": "hosting", "country": "DE"},
        45090: {"name": "TENCENT", "description": "Tencent Cloud", "type": "hosting", "country": "CN"},
        37963: {"name": "ALIBABA", "description": "Alibaba Cloud", "type": "hosting", "country": "CN"},
        55990: {"name": "HUAWEI", "description": "Huawei Cloud", "type": "hosting", "country": "CN"},

        # ─── CDN Providers ───
        13335: {"name": "CLOUDFLARENET", "description": "Cloudflare", "type": "cdn", "country": "US"},
        20940: {"name": "AKAMAI", "description": "Akamai Technologies", "type": "cdn", "country": "US"},
        22822: {"name": "LLNW", "description": "Limelight Networks", "type": "cdn", "country": "US"},
        54113: {"name": "FASTLY", "description": "Fastly", "type": "cdn", "country": "US"},

        # ─── VPN Providers ───
        9009: {"name": "M247", "description": "M247 (NordVPN)", "type": "vpn", "country": "GB"},
        212238: {"name": "DATACAMP", "description": "Datacamp (Surfshark)", "type": "vpn", "country": "NL"},
        60068: {"name": "DATACAMP", "description": "Datacamp", "type": "vpn", "country": "NL"},
        39351: {"name": "EXPRESSVPN", "description": "ExpressVPN", "type": "vpn", "country": "VG"},
        51765: {"name": "M247-UK", "description": "M247 UK", "type": "vpn", "country": "GB"},
        202425: {"name": "IPV6", "description": "IPV6 Internet", "type": "vpn", "country": "GB"},

        # ─── Major ISPs ───
        # Egypt
        36992: {"name": "ETISALAT", "description": "Etisalat Egypt", "type": "isp", "country": "EG"},
        24863: {"name": "LINKdotNET", "description": "Link Egypt", "type": "isp", "country": "EG"},
        8452: {"name": "TE-AS", "description": "Telecom Egypt", "type": "isp", "country": "EG"},
        5536: {"name": "VODAFONE-EG", "description": "Vodafone Egypt", "type": "isp", "country": "EG"},
        132061: {"name": "ORANGE-EG", "description": "Orange Egypt", "type": "isp", "country": "EG"},

        # US
        7018: {"name": "ATT-INTERNET4", "description": "AT&T", "type": "isp", "country": "US"},
        701: {"name": "UUNET", "description": "Verizon Business", "type": "isp", "country": "US"},
        7922: {"name": "COMCAST-7922", "description": "Comcast", "type": "isp", "country": "US"},
        20115: {"name": "CHARTER-20115", "description": "Charter Communications", "type": "isp", "country": "US"},
        22773: {"name": "ASN-CXA-ALL-CCI-22773", "description": "Cox Communications", "type": "isp", "country": "US"},
        6128: {"name": "CABLE-NET-1", "description": "Cablevision", "type": "isp", "country": "US"},

        # EU
        3320: {"name": "DTAG", "description": "Deutsche Telekom", "type": "isp", "country": "DE"},
        3215: {"name": "ORANGE", "description": "Orange S.A.", "type": "isp", "country": "FR"},
        3352: {"name": "TELEFONICA", "description": "Telefonica", "type": "isp", "country": "ES"},
        3269: {"name": "TELECOM-ITALIA", "description": "Telecom Italia", "type": "isp", "country": "IT"},
        2856: {"name": "BT", "description": "British Telecom", "type": "isp", "country": "GB"},

        # Asia
        4134: {"name": "CHINANET", "description": "China Telecom", "type": "isp", "country": "CN"},
        4837: {"name": "CHINA169", "description": "China Unicom", "type": "isp", "country": "CN"},
        9808: {"name": "CMNET", "description": "China Mobile", "type": "isp", "country": "CN"},
        2516: {"name": "KDDI", "description": "KDDI Corporation", "type": "isp", "country": "JP"},
        4713: {"name": "OCN", "description": "NTT Communications", "type": "isp", "country": "JP"},
        9318: {"name": "SKBROADBAND", "description": "SK Broadband", "type": "isp", "country": "KR"},
        4766: {"name": "KORNET", "description": "Korea Telecom", "type": "isp", "country": "KR"},

        # ─── Education ───
        27: {"name": "UVA", "description": "University of Virginia", "type": "education", "country": "US"},
        3: {"name": "MIT", "description": "Massachusetts Institute of Technology", "type": "education", "country": "US"},
        32: {"name": "STANFORD", "description": "Stanford University", "type": "education", "country": "US"},
        55: {"name": "UPENN", "description": "University of Pennsylvania", "type": "education", "country": "US"},
        225: {"name": "UCLA", "description": "University of California, Los Angeles", "type": "education", "country": "US"},

        # ─── Government ───
        749: {"name": "DNIC", "description": "US Department of Defense", "type": "government", "country": "US"},
        668: {"name": "DNIC-AS-00668", "description": "US DoD Network Information Center", "type": "government", "country": "US"},
        2635: {"name": "NASA", "description": "NASA", "type": "government", "country": "US"},
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
                logger.error("asn_lookup_redis_init_failed", error=str(e))
                return None
        return cls._redis_client

    @staticmethod
    def _cache_key(asn: int) -> str:
        """بتبني مفتاح الـ cache."""
        return f"asn:{asn}"

    @staticmethod
    def _ip_cache_key(ip: str) -> str:
        """بتبني مفتاح الـ cache للـ IP."""
        return f"asn_ip:{ip}"

    # ─── Main API ──────────────────────────────────────────

    @classmethod
    async def lookup(cls, asn: int) -> Dict[str, Any]:
        """
        بيدور على معلومات ASN.

        Args:
            asn: رقم الـ ASN

        Returns:
            dict فيه:
            - asn
            - name
            - description
            - type (hosting/isp/vpn/cdn/education/government/business/unknown)
            - country
            - is_hosting
            - is_vpn
            - is_isp
            - is_cdn
            - source (cache/database)
        """
        if not isinstance(asn, int) or asn <= 0:
            return cls._unknown_result(asn)

        # 1. جرب Redis cache
        cached = await cls._get_from_cache(asn)
        if cached:
            cached["source"] = "cache"
            return cached

        # 2. جرب Known ASN Database
        result = cls._lookup_from_database(asn)

        # 3. خزن في Redis
        await cls._store_in_cache(asn, result)

        return result

    @classmethod
    async def lookup_by_ip(cls, ip: str) -> Dict[str, Any]:
        """
        بيدور على ASN من IP.

        ملاحظة: ده بيحتاج GeoIP lookup الأول عشان يجيب الـ ASN.
        """
        if not ip:
            return cls._unknown_result(0)

        try:
            # استخدم GeoIP عشان يجيب الـ ASN
            from app.core.geoip import GeoIP

            geo_info = await GeoIP.lookup(ip)
            asn = geo_info.get("asn")

            if not asn:
                return cls._unknown_result(0, ip=ip)

            result = await cls.lookup(asn)

            # ضيف معلومات إضافية من GeoIP
            result["ip"] = ip
            result["geo_country"] = geo_info.get("country")
            result["isp"] = geo_info.get("isp")

            return result

        except Exception as e:
            logger.error("asn_lookup_by_ip_failed", ip=ip, error=str(e))
            return cls._unknown_result(0, ip=ip)

    @classmethod
    def _lookup_from_database(cls, asn: int) -> Dict[str, Any]:
        """بيدور على ASN في الـ database."""
        if asn in cls.KNOWN_ASNS:
            data = cls.KNOWN_ASNS[asn].copy()
            data["asn"] = asn
            data["source"] = "database"
            data["is_hosting"] = data["type"] == "hosting"
            data["is_vpn"] = data["type"] == "vpn"
            data["is_isp"] = data["type"] == "isp"
            data["is_cdn"] = data["type"] == "cdn"
            return data

        # Unknown ASN
        return cls._unknown_result(asn)

    @classmethod
    def _unknown_result(cls, asn: int, ip: str = "") -> Dict[str, Any]:
        """نتيجة فاضية."""
        result = {
            "asn": asn,
            "name": None,
            "description": None,
            "type": "unknown",
            "country": None,
            "is_hosting": False,
            "is_vpn": False,
            "is_isp": False,
            "is_cdn": False,
            "source": "unknown",
        }
        if ip:
            result["ip"] = ip
        return result

    # ─── Cache ─────────────────────────────────────────────

    @classmethod
    async def _get_from_cache(cls, asn: int) -> Optional[Dict[str, Any]]:
        """بيجيب من Redis cache."""
        client = cls.get_client()
        if not client:
            return None

        try:
            key = cls._cache_key(asn)
            data = await client.get(key)
            if data:
                return json.loads(data)
        except Exception as e:
            logger.warning("asn_cache_get_failed", error=str(e))

        return None

    @classmethod
    async def _store_in_cache(cls, asn: int, data: Dict[str, Any]) -> None:
        """بيخزن في Redis cache."""
        client = cls.get_client()
        if not client:
            return

        try:
            key = cls._cache_key(asn)
            await client.setex(key, cls.CACHE_TTL, json.dumps(data))
        except Exception as e:
            logger.warning("asn_cache_set_failed", error=str(e))

    # ─── Classification ────────────────────────────────────

    @classmethod
    def is_hosting_asn(cls, asn: int) -> bool:
        """بيفحص لو الـ ASN hosting."""
        if asn in cls.KNOWN_ASNS:
            return cls.KNOWN_ASNS[asn].get("type") == "hosting"
        return False

    @classmethod
    def is_vpn_asn(cls, asn: int) -> bool:
        """بيفحص لو الـ ASN VPN."""
        if asn in cls.KNOWN_ASNS:
            return cls.KNOWN_ASNS[asn].get("type") == "vpn"
        return False

    @classmethod
    def is_cdn_asn(cls, asn: int) -> bool:
        """بيفحص لو الـ ASN CDN."""
        if asn in cls.KNOWN_ASNS:
            return cls.KNOWN_ASNS[asn].get("type") == "cdn"
        return False

    @classmethod
    def is_isp_asn(cls, asn: int) -> bool:
        """بيفحص لو الـ ASN ISP."""
        if asn in cls.KNOWN_ASNS:
            return cls.KNOWN_ASNS[asn].get("type") == "isp"
        return False

    @classmethod
    def is_education_asn(cls, asn: int) -> bool:
        """بيفحص لو الـ ASN education."""
        if asn in cls.KNOWN_ASNS:
            return cls.KNOWN_ASNS[asn].get("type") == "education"
        return False

    @classmethod
    def is_government_asn(cls, asn: int) -> bool:
        """بيفحص لو الـ ASN government."""
        if asn in cls.KNOWN_ASNS:
            return cls.KNOWN_ASNS[asn].get("type") == "government"
        return False

    # ─── Risk Assessment ──────────────────────────────────

    @classmethod
    async def get_risk_score(cls, asn: int) -> int:
        """
        بترجع risk score للـ ASN (0-100).

        Factors:
        - hosting: +30
        - vpn: +50
        - unknown: +20
        """
        info = await cls.lookup(asn)

        score = 0

        if info.get("is_hosting"):
            score += 30
        if info.get("is_vpn"):
            score += 50
        if info.get("type") == "unknown":
            score += 20

        return min(score, 100)

    @classmethod
    async def is_suspicious_asn(cls, asn: int) -> bool:
        """
        بيفحص لو الـ ASN مشبوه.

        المشبوه:
        - VPN
        - Hosting (معظم المستخدمين مش هيكونوا من datacenters)
        """
        info = await cls.lookup(asn)
        return info.get("is_vpn", False) or info.get("is_hosting", False)

    # ─── Statistics ───────────────────────────────────────

    @classmethod
    def get_all_known_asns(cls) -> Dict[int, Dict[str, Any]]:
        """بترجع كل الـ ASNs المعروفة."""
        return dict(cls.KNOWN_ASNS)

    @classmethod
    def get_asns_by_type(cls, as_type: str) -> list:
        """بترجع كل الـ ASNs من نوع معين."""
        return [
            asn for asn, data in cls.KNOWN_ASNS.items()
            if data.get("type") == as_type
        ]

    @classmethod
    def add_known_asn(
        cls,
        asn: int,
        name: str,
        description: str,
        as_type: str,
        country: str,
    ) -> None:
        """بيضيف ASN للـ database."""
        if as_type not in cls.AS_TYPES:
            raise ValueError(f"Invalid AS type: {as_type}")

        cls.KNOWN_ASNS[asn] = {
            "name": name,
            "description": description,
            "type": as_type,
            "country": country,
        }
        logger.info("asn_added", asn=asn, name=name, type=as_type)

    # ─── Utilities ─────────────────────────────────────────

    @classmethod
    async def clear_cache(cls, asn: Optional[int] = None) -> None:
        """بيمسح cache."""
        client = cls.get_client()
        if not client:
            return

        try:
            if asn:
                await client.delete(cls._cache_key(asn))
                logger.info("asn_cache_cleared", asn=asn)
            else:
                async for key in client.scan_iter(match="asn:*", count=100):
                    await client.delete(key)
                logger.info("asn_cache_cleared_all")
        except Exception as e:
            logger.error("asn_cache_clear_failed", error=str(e))

    @classmethod
    async def close(cls) -> None:
        """بتقفل Redis."""
        if cls._redis_client:
            await cls._redis_client.close()
            cls._redis_client = None