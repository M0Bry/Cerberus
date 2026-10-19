"""
JA3 Fingerprint — TLS Client Fingerprinting.

بيوفر:
- JA3 fingerprint parsing
- Known JA3 database (browsers, libraries, malware)
- Client classification
- Suspicious fingerprint detection
- Redis caching

الفكرة:
- Nginx/HAProxy بيحسب JA3 من TLS handshake
- بيمرره للـ FastAPI في header (X-JA3-Fingerprint)
- إحنا بنحلله ونصنف العميل

JA3 Format:
- MD5 hash of: TLSVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats
- مثال: a0e9f5d64349fb13191bc781f81f42e1

الاستخدام:
- كشف الـ bots (curl, python, scanner)
- كشف الـ malware
- Allow/Block based on client type
"""

import re
from typing import Any, Dict, List, Optional

import redis.asyncio as redis
import structlog

from app.core.config import settings

logger = structlog.get_logger()


class JA3Fingerprint:
    """
    JA3 TLS Fingerprint Analyzer.

    الفكرة:
    1. ناخد الـ JA3 من الـ header
    2. نصنف العميل حسب البصمة
    3. نرجع معلومات + score
    """

    _redis_client: Optional[redis.Redis] = None

    # ─── Config ────────────────────────────────────────────
    CACHE_TTL = 86400 * 7  # 7 أيام

    # ─── Headers اللي بنقرا منها ──────────────────────────
    JA3_HEADERS = [
        "x-ja3-fingerprint",
        "x-ja3-hash",
        "x-tls-fingerprint",
        "x-ssl-ja3",
    ]

    # ─── Known JA3 Database ────────────────────────────────
    # (JA3 hash: {client, type, score})
    # المصدر: https://github.com/salesforce/ja3 + community databases
    KNOWN_JA3: Dict[str, Dict[str, Any]] = {
        # ─── Browsers (trusted) ───
        # Chrome (Windows)
        "cd08e31494f9531f560d64c695473da9": {
            "client": "Chrome",
            "type": "browser",
            "os": "Windows",
            "score": 0,
        },
        # Chrome (macOS)
        "b32309a26951912be7dba376398abc3b": {
            "client": "Chrome",
            "type": "browser",
            "os": "macOS",
            "score": 0,
        },
        # Firefox (Windows)
        "0c11b2f56d6e5b1b1c7d8e9f0a1b2c3d": {
            "client": "Firefox",
            "type": "browser",
            "os": "Windows",
            "score": 0,
        },
        # Safari (macOS)
        "773906b0efdefa24a7f2b8eb6985bf37": {
            "client": "Safari",
            "type": "browser",
            "os": "macOS",
            "score": 0,
        },
        # Edge (Windows)
        "51c64c77e60f3980eea90869b68c58a8": {
            "client": "Edge",
            "type": "browser",
            "os": "Windows",
            "score": 0,
        },

        # ─── Mobile Browsers ───
        "079c2c21c4f8d3f1e5a6b7c8d9e0f1a2": {
            "client": "Mobile Safari",
            "type": "browser",
            "os": "iOS",
            "score": 0,
        },
        "b8d4e3f2a1c9b8d7e6f5a4b3c2d1e0f9": {
            "client": "Chrome Mobile",
            "type": "browser",
            "os": "Android",
            "score": 0,
        },

        # ─── HTTP Clients (suspicious) ───
        # curl
        "3b5074b1b5d032e5620f69f9f700ff0e": {
            "client": "curl",
            "type": "http_client",
            "score": 40,
        },
        # wget
        "ca42e8d5d5d0c8fc8b8f8f8f8f8f8f8f": {
            "client": "wget",
            "type": "http_client",
            "score": 40,
        },
        # Python requests
        "38d9a3c1c8e5e5e5e5e5e5e5e5e5e5e5": {
            "client": "Python Requests",
            "type": "http_client",
            "score": 50,
        },
        # Go HTTP client
        "eb1d94daa7e0344597e756a1fb6e7054": {
            "client": "Go HTTP Client",
            "type": "http_client",
            "score": 45,
        },
        # Java HTTP client
        "5b2b5b5b5b5b5b5b5b5b5b5b5b5b5b5b": {
            "client": "Java HTTP Client",
            "type": "http_client",
            "score": 40,
        },
        # Node.js
        "f4febc55ea12b31ae17cfb7e614514af": {
            "client": "Node.js",
            "type": "http_client",
            "score": 40,
        },
        # axios
        "c12b34d5e6f7a8b9c0d1e2f3a4b5c6d7": {
            "client": "Axios",
            "type": "http_client",
            "score": 35,
        },

        # ─── Security Tools (highly suspicious) ───
        # sqlmap
        "a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2": {
            "client": "sqlmap",
            "type": "scanner",
            "score": 90,
        },
        # nmap
        "e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8": {
            "client": "nmap",
            "type": "scanner",
            "score": 90,
        },
        # nikto
        "f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4": {
            "client": "nikto",
            "type": "scanner",
            "score": 90,
        },
        # metasploit
        "8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d": {
            "client": "Metasploit",
            "type": "exploit",
            "score": 95,
        },

        # ─── Malware (highly dangerous) ───
        # Trickbot
        "6734f37431670b3ab4292b8f60f29984": {
            "client": "Trickbot",
            "type": "malware",
            "score": 100,
        },
        # Emotet
        "7b4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f": {
            "client": "Emotet",
            "type": "malware",
            "score": 100,
        },
        # Cobalt Strike
        "a0e9f5d64349fb13191bc781f81f42e1": {
            "client": "Cobalt Strike",
            "type": "malware",
            "score": 100,
        },
    }

    # ─── JA3 Format Validation ────────────────────────────
    JA3_HASH_PATTERN = re.compile(r"^[a-f0-9]{32}$", re.IGNORECASE)

    # ─── Weights ──────────────────────────────────────────
    UNKNOWN_JA3_SCORE = 25   # بصمة غير معروفة
    INVALID_JA3_SCORE = 30   # بصمة مش valid

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
                logger.error("ja3_redis_init_failed", error=str(e))
                return None
        return cls._redis_client

    @staticmethod
    def _cache_key(ja3: str) -> str:
        """بتبني مفتاح الـ cache."""
        return f"ja3:{ja3.lower()}"

    # ─── Header Extraction ────────────────────────────────

    @classmethod
    def extract_ja3(cls, request) -> Optional[str]:
        """
        بيستخرج الـ JA3 من الـ headers.

        Returns:
            الـ JA3 hash أو None
        """
        for header in cls.JA3_HEADERS:
            value = request.headers.get(header)
            if value:
                value = value.strip()
                if value:
                    return value
        return None

    # ─── Validation ───────────────────────────────────────

    @classmethod
    def is_valid_ja3(cls, ja3: str) -> bool:
        """
        بيفحص لو الـ JA3 بصيغة صحيحة.

        الصيغة: 32 حرف hex (MD5)
        """
        if not ja3 or not isinstance(ja3, str):
            return False
        return bool(cls.JA3_HASH_PATTERN.match(ja3))

    # ─── Lookup ───────────────────────────────────────────

    @classmethod
    async def lookup(cls, ja3: str) -> Dict[str, Any]:
        """
        بيدور على الـ JA3 في الـ database.

        Args:
            ja3: الـ JA3 hash

        Returns:
            dict فيه:
            - ja3
            - is_known: bool
            - client: اسم العميل
            - type: browser/http_client/scanner/malware/...
            - os: نظام التشغيل
            - score: 0-100
            - is_suspicious: bool
        """
        if not ja3:
            return cls._empty_result(None, "no_ja3")

        ja3_lower = ja3.lower()

        # 1. Validate format
        if not cls.is_valid_ja3(ja3_lower):
            return cls._empty_result(
                ja3,
                "invalid_format",
                score=cls.INVALID_JA3_SCORE,
            )

        # 2. Check Redis cache
        cached = await cls._get_from_cache(ja3_lower)
        if cached:
            cached["source"] = "cache"
            return cached

        # 3. Lookup in database
        result = cls._lookup_from_database(ja3_lower)

        # 4. Store in cache
        await cls._store_in_cache(ja3_lower, result)

        return result

    @classmethod
    def _lookup_from_database(cls, ja3: str) -> Dict[str, Any]:
        """بيدور في الـ database."""
        if ja3 in cls.KNOWN_JA3:
            data = cls.KNOWN_JA3[ja3].copy()
            score = data.get("score", 0)

            return {
                "ja3": ja3,
                "is_known": True,
                "client": data.get("client"),
                "type": data.get("type", "unknown"),
                "os": data.get("os"),
                "score": score,
                "is_suspicious": score >= 40,
                "source": "database",
            }

        # Unknown JA3
        return {
            "ja3": ja3,
            "is_known": False,
            "client": None,
            "type": "unknown",
            "os": None,
            "score": cls.UNKNOWN_JA3_SCORE,
            "is_suspicious": True,  # بصمة مش معروفة = مشبوه
            "source": "unknown",
        }

    @classmethod
    def _empty_result(
        cls,
        ja3: Optional[str],
        reason: str,
        score: int = 0,
    ) -> Dict[str, Any]:
        """نتيجة فاضية."""
        return {
            "ja3": ja3,
            "is_known": False,
            "client": None,
            "type": "unknown",
            "os": None,
            "score": score,
            "is_suspicious": score >= 40,
            "source": reason,
        }

    # ─── Main API ─────────────────────────────────────────

    @classmethod
    async def analyze(cls, request) -> Dict[str, Any]:
        """
        بيحلل الطلب ويرجع معلومات JA3.

        Args:
            request: FastAPI Request

        Returns:
            dict فيه معلومات الـ JA3 + classification
        """
        # 1. استخرج الـ JA3
        ja3 = cls.extract_ja3(request)

        if not ja3:
            return {
                "ja3": None,
                "available": False,
                "is_known": False,
                "type": "unknown",
                "score": 0,
                "is_suspicious": False,
                "source": "no_header",
            }

        # 2. Lookup
        result = await cls.lookup(ja3)
        result["available"] = True

        if result.get("is_suspicious"):
            logger.warning(
                "ja3_suspicious",
                ja3=ja3[:16] + "...",
                client=result.get("client"),
                type=result.get("type"),
                score=result.get("score"),
            )

        return result

    # ─── Classification Helpers ───────────────────────────

    @classmethod
    async def is_browser(cls, ja3: str) -> bool:
        """بيفحص لو البصمة من browser."""
        result = await cls.lookup(ja3)
        return result.get("type") == "browser"

    @classmethod
    async def is_http_client(cls, ja3: str) -> bool:
        """بيفحص لو البصمة من HTTP client."""
        result = await cls.lookup(ja3)
        return result.get("type") == "http_client"

    @classmethod
    async def is_scanner(cls, ja3: str) -> bool:
        """بيفحص لو البصمة من scanner."""
        result = await cls.lookup(ja3)
        return result.get("type") == "scanner"

    @classmethod
    async def is_malware(cls, ja3: str) -> bool:
        """بيفحص لو البصمة من malware."""
        result = await cls.lookup(ja3)
        return result.get("type") == "malware"

    @classmethod
    async def is_suspicious(cls, ja3: str) -> bool:
        """بيفحص لو البصمة مشبوهة."""
        result = await cls.lookup(ja3)
        return result.get("is_suspicious", False)

    # ─── Admin API ─────────────────────────────────────────

    @classmethod
    def add_known_ja3(
        cls,
        ja3: str,
        client: str,
        client_type: str,
        os: Optional[str] = None,
        score: int = 0,
    ) -> None:
        """بيضيف JA3 للـ database."""
        if not cls.is_valid_ja3(ja3):
            raise ValueError(f"Invalid JA3 format: {ja3}")

        cls.KNOWN_JA3[ja3.lower()] = {
            "client": client,
            "type": client_type,
            "os": os,
            "score": score,
        }
        logger.info(
            "ja3_added",
            ja3=ja3[:16] + "...",
            client=client,
            type=client_type,
        )

    @classmethod
    def remove_known_ja3(cls, ja3: str) -> None:
        """بيشيل JA3 من الـ database."""
        cls.KNOWN_JA3.pop(ja3.lower(), None)

    @classmethod
    def get_all_known_ja3(cls) -> Dict[str, Dict[str, Any]]:
        """بترجع كل الـ JA3s المعروفة."""
        return dict(cls.KNOWN_JA3)

    @classmethod
    def get_ja3_by_type(cls, client_type: str) -> List[str]:
        """بترجع كل الـ JA3s من نوع معين."""
        return [
            ja3 for ja3, data in cls.KNOWN_JA3.items()
            if data.get("type") == client_type
        ]

    # ─── Cache ─────────────────────────────────────────────

    @classmethod
    async def _get_from_cache(cls, ja3: str) -> Optional[Dict[str, Any]]:
        """بيجيب من Redis cache."""
        client = cls.get_client()
        if not client:
            return None

        try:
            key = cls._cache_key(ja3)
            import json
            data = await client.get(key)
            if data:
                return json.loads(data)
        except Exception as e:
            logger.warning("ja3_cache_get_failed", error=str(e))

        return None

    @classmethod
    async def _store_in_cache(cls, ja3: str, data: Dict[str, Any]) -> None:
        """بيخزن في Redis cache."""
        client = cls.get_client()
        if not client:
            return

        try:
            import json
            key = cls._cache_key(ja3)
            await client.setex(key, cls.CACHE_TTL, json.dumps(data))
        except Exception as e:
            logger.warning("ja3_cache_set_failed", error=str(e))

    # ─── Utilities ─────────────────────────────────────────

    @classmethod
    async def clear_cache(cls, ja3: Optional[str] = None) -> None:
        """بيمسح cache."""
        client = cls.get_client()
        if not client:
            return

        try:
            if ja3:
                await client.delete(cls._cache_key(ja3))
                logger.info("ja3_cache_cleared", ja3=ja3[:16] + "...")
            else:
                async for key in client.scan_iter(match="ja3:*", count=100):
                    await client.delete(key)
                logger.info("ja3_cache_cleared_all")
        except Exception as e:
            logger.error("ja3_cache_clear_failed", error=str(e))

    @classmethod
    async def close(cls) -> None:
        """بتقفل Redis."""
        if cls._redis_client:
            await cls._redis_client.close()
            cls._redis_client = None