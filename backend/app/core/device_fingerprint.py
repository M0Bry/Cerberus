"""
Device Fingerprint — Generates unique device signatures.

بيوفر:
- Device fingerprinting from request headers
- Stable fingerprint (نفس الجهاز دايماً → نفس البصمة)
- Multiple fingerprint types (headers, TLS, HTTP/2)
- Redis-backed storage
- Per-device tracking

الفكرة:
- نجمع كل الإشارات من الطلب
- نحولها لـ hash
- الـ hash = بصمة الجهاز

الإشارات:
- User-Agent
- Accept-Language
- Accept-Encoding
- Accept-Charset
- Sec-CH-UA (Client Hints)
- DNT (Do Not Track)
- Upgrade-Insecure-Requests
- Connection
- TLS fingerprint (لو موجود)
- HTTP/2 fingerprint

الاستخدام:
- تتبع الأجهزة المشبوهة
- كشف الـ Session Hijacking
- منع multi-accounting
- تحليل الـ bot traffic
"""

import hashlib
import time
from typing import Any, Dict, List, Optional

import redis.asyncio as redis
import structlog

from app.core.config import settings

logger = structlog.get_logger()


class DeviceFingerprint:
    """
    Device Fingerprint Generator.

    الفكرة:
    - نجمع الإشارات من الطلب
    - نرتبهم بشكل ثابت
    - نحسب hash
    - الـ hash = بصمة الجهاز
    """

    _redis_client: Optional[redis.Redis] = None

    # ─── Headers اللي بتساهم في البصمة ────────────────────
    FINGERPRINT_HEADERS = [
        "user-agent",
        "accept",
        "accept-language",
        "accept-encoding",
        "accept-charset",
        "dnt",
        "upgrade-insecure-requests",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "sec-fetch-site",
        "sec-fetch-mode",
        "sec-fetch-dest",
        "connection",
        "cache-control",
        "pragma",
    ]

    # ─── Headers لـ Proxy (TLS fingerprints) ───────────────
    PROXY_FINGERPRINT_HEADERS = [
        "x-ja3-fingerprint",
        "x-ja3-hash",
        "x-ja4-fingerprint",
        "x-tls-fingerprint",
        "x-http2-fingerprint",
        "x-ssl-cipher",
        "x-ssl-protocol",
    ]

    # ─── Max Values ────────────────────────────────────────
    MAX_HEADER_LENGTH = 512
    FINGERPRINT_TTL = 86400 * 30  # 30 يوم

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
                logger.error("device_fingerprint_redis_init_failed", error=str(e))
                return None
        return cls._redis_client

    # ─── Fingerprint Generation ────────────────────────────

    @classmethod
    def generate(cls, request) -> Dict[str, Any]:
        """
        بيولد بصمة الجهاز من الطلب.

        Args:
            request: FastAPI Request

        Returns:
            dict فيه:
            - fingerprint: البصمة (hash)
            - components: المكونات اللي دخلت في البصمة
            - ip: الـ IP
            - user_agent: الـ UA
        """
        components = cls._extract_components(request)
        fingerprint = cls._compute_hash(components)

        return {
            "fingerprint": fingerprint,
            "components": components,
            "component_count": len(components),
        }

    @classmethod
    def _extract_components(cls, request) -> Dict[str, str]:
        """
        بيستخرج المكونات اللي بتدخل في البصمة.
        """
        components: Dict[str, str] = {}

        # 1. Headers الأساسية
        for header_name in cls.FINGERPRINT_HEADERS:
            value = request.headers.get(header_name, "")
            if value:
                # نظف القيمة
                value = value.strip()[:cls.MAX_HEADER_LENGTH]
                components[header_name] = value

        # 2. Proxy headers (TLS fingerprints)
        for header_name in cls.PROXY_FINGERPRINT_HEADERS:
            value = request.headers.get(header_name, "")
            if value:
                value = value.strip()[:cls.MAX_HEADER_LENGTH]
                components[header_name] = value

        # 3. HTTP Method
        components["_method"] = request.method

        # 4. HTTP Version
        http_version = getattr(request, "scope", {}).get("http_version", "1.1")
        components["_http_version"] = http_version

        return components

    @staticmethod
    def _compute_hash(components: Dict[str, str]) -> str:
        """
        بيحسب hash من المكونات.

        مهم: بنرتب المكونات أبجدياً عشان:
        - نفس الجهاز → نفس الـ hash
        - حتى لو ترتيب الـ headers مختلف
        """
        if not components:
            return "unknown"

        # رتب المكونات أبجدياً
        sorted_items = sorted(components.items())

        # ادمج
        combined = "|".join(f"{k}={v}" for k, v in sorted_items)

        # احسب SHA-256
        return hashlib.sha256(combined.encode("utf-8")).hexdigest()[:32]

    # ─── Fingerprint Storage ──────────────────────────────

    @classmethod
    async def store(
        cls,
        fingerprint: str,
        ip: str,
        user_agent: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        بيخزن البصمة في Redis.

        Args:
            fingerprint: البصمة
            ip: الـ IP
            user_agent: الـ UA
            metadata: بيانات إضافية
        """
        client = cls.get_client()
        if not client:
            return

        try:
            key = f"device:fp:{fingerprint}"
            now = time.time()

            # 1. سجل آخر مشاهدة
            await client.hset(
                key,
                mapping={
                    "fingerprint": fingerprint,
                    "last_ip": ip,
                    "user_agent": user_agent[:512],
                    "last_seen": str(now),
                    "first_seen": str(now),
                },
            )
            await client.expire(key, cls.FINGERPRINT_TTL)

            # 2. سجل كل الـ IPs المرتبطة بالجهاز
            ip_set_key = f"device:ips:{fingerprint}"
            await client.sadd(ip_set_key, ip)
            await client.expire(ip_set_key, cls.FINGERPRINT_TTL)

            # 3. سجل الأجهزة لكل IP
            ip_devices_key = f"ip:devices:{ip}"
            await client.sadd(ip_devices_key, fingerprint)
            await client.expire(ip_devices_key, cls.FINGERPRINT_TTL)

        except Exception as e:
            logger.error("device_fingerprint_store_failed", error=str(e))

    @classmethod
    async def get_info(cls, fingerprint: str) -> Optional[Dict[str, Any]]:
        """بترجع معلومات الجهاز."""
        client = cls.get_client()
        if not client:
            return None

        try:
            key = f"device:fp:{fingerprint}"
            data = await client.hgetall(key)

            if not data:
                return None

            # جيب الـ IPs المرتبطة
            ip_set_key = f"device:ips:{fingerprint}"
            ips = await client.smembers(ip_set_key)

            return {
                "fingerprint": fingerprint,
                "first_seen": float(data.get("first_seen", 0)),
                "last_seen": float(data.get("last_seen", 0)),
                "last_ip": data.get("last_ip", ""),
                "user_agent": data.get("user_agent", ""),
                "associated_ips": list(ips),
                "ip_count": len(ips),
            }

        except Exception as e:
            logger.error("device_fingerprint_get_info_failed", error=str(e))
            return None

    # ─── Device Analysis ──────────────────────────────────

    @classmethod
    async def get_device_ips(cls, fingerprint: str) -> List[str]:
        """بترجع كل الـ IPs المرتبطة بجهاز."""
        client = cls.get_client()
        if not client:
            return []

        try:
            ip_set_key = f"device:ips:{fingerprint}"
            return list(await client.smembers(ip_set_key))
        except Exception as e:
            logger.error("device_fingerprint_get_ips_failed", error=str(e))
            return []

    @classmethod
    async def get_ip_devices(cls, ip: str) -> List[str]:
        """بترجع كل الأجهزة المرتبطة بـ IP."""
        client = cls.get_client()
        if not client:
            return []

        try:
            ip_devices_key = f"ip:devices:{ip}"
            return list(await client.smembers(ip_devices_key))
        except Exception as e:
            logger.error("device_fingerprint_get_devices_failed", error=str(e))
            return []

    @classmethod
    async def is_suspicious(cls, fingerprint: str, threshold: int = 5) -> bool:
        """
        بيفحص لو الجهاز مشبوه.

        المعيار:
        - لو الجهاز مرتبط بأكتر من threshold IP
        """
        ips = await cls.get_device_ips(fingerprint)
        return len(ips) > threshold

    # ─── Component Analysis ───────────────────────────────

    @classmethod
    def get_user_agent_info(cls, user_agent: str) -> Dict[str, Any]:
        """
        بيفكك الـ User-Agent.
        """
        if not user_agent:
            return {
                "browser": None,
                "os": None,
                "device": None,
                "is_bot": False,
            }

        ua_lower = user_agent.lower()

        # Browser
        browser = None
        if "chrome" in ua_lower and "edg" not in ua_lower:
            browser = "Chrome"
        elif "firefox" in ua_lower:
            browser = "Firefox"
        elif "safari" in ua_lower and "chrome" not in ua_lower:
            browser = "Safari"
        elif "edg" in ua_lower:
            browser = "Edge"
        elif "opera" in ua_lower or "opr" in ua_lower:
            browser = "Opera"

        # OS
        os_name = None
        if "windows" in ua_lower:
            os_name = "Windows"
        elif "mac os" in ua_lower or "macintosh" in ua_lower:
            os_name = "macOS"
        elif "linux" in ua_lower:
            os_name = "Linux"
        elif "android" in ua_lower:
            os_name = "Android"
        elif "iphone" in ua_lower or "ipad" in ua_lower:
            os_name = "iOS"

        # Device
        device = None
        if "mobile" in ua_lower or "android" in ua_lower or "iphone" in ua_lower:
            device = "Mobile"
        elif "tablet" in ua_lower or "ipad" in ua_lower:
            device = "Tablet"
        else:
            device = "Desktop"

        # Bot
        bot_keywords = ["bot", "crawl", "spider", "curl", "wget", "python", "java"]
        is_bot = any(kw in ua_lower for kw in bot_keywords)

        return {
            "browser": browser,
            "os": os_name,
            "device": device,
            "is_bot": is_bot,
        }

    @classmethod
    async def get_full_analysis(
        cls,
        request,
    ) -> Dict[str, Any]:
        """
        بيعمل تحليل كامل للجهاز.
        """
        # 1. ولد البصمة
        fp_data = cls.generate(request)
        fingerprint = fp_data["fingerprint"]

        # 2. جيب معلومات من Redis
        info = await cls.get_info(fingerprint)

        # 3. حلل الـ User-Agent
        ua = request.headers.get("user-agent", "")
        ua_info = cls.get_user_agent_info(ua)

        # 4. الـ IPs المرتبطة
        associated_ips = await cls.get_device_ips(fingerprint)

        # 5. هل مشبوه؟
        is_suspicious = len(associated_ips) > 5

        return {
            "fingerprint": fingerprint,
            "components": fp_data["components"],
            "component_count": fp_data["component_count"],
            "ua_info": ua_info,
            "first_seen": info["first_seen"] if info else None,
            "last_seen": info["last_seen"] if info else None,
            "associated_ips": associated_ips,
            "ip_count": len(associated_ips),
            "is_suspicious": is_suspicious,
        }

    # ─── Utilities ─────────────────────────────────────────

    @classmethod
    async def reset(cls, fingerprint: str) -> None:
        """بتمسح بصمة جهاز."""
        client = cls.get_client()
        if not client:
            return

        try:
            keys = [
                f"device:fp:{fingerprint}",
                f"device:ips:{fingerprint}",
            ]
            await client.delete(*keys)
            logger.info("device_fingerprint_reset", fingerprint=fingerprint)
        except Exception as e:
            logger.error("device_fingerprint_reset_failed", error=str(e))

    @classmethod
    async def close(cls) -> None:
        """بتقفل Redis."""
        if cls._redis_client:
            await cls._redis_client.close()
            cls._redis_client = None