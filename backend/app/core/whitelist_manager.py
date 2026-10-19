"""
Whitelist Manager — Manages whitelists for trusted entities.

بيوفر:
- IP whitelist (with CIDR support)
- User whitelist
- API Key whitelist
- Path whitelist
- Time-based whitelist
- Temporary whitelist (with TTL)
- Permanent whitelist
- Redis-backed

الفكرة:
- كل نوع له prefix في Redis
- CIDR بيتم عبر ipaddress
- TTL للـ temporary

الاستخدام:
- تخطي Rate Limiting للموظفين
- Admin endpoints protection
- API keys for services
- Health checks exemption
"""

import ipaddress
import json
import time
from typing import Any, Dict, List, Optional, Set

import redis.asyncio as redis
import structlog

from app.core.config import settings

logger = structlog.get_logger()


class WhitelistManager:
    """
    Whitelist Manager.

    الفكرة:
    - كل نوع whitelist له prefix
    - بعض الأنواع بندعم CIDR (IPs)
    - TTL اختياري لكل entry
    """

    _redis_client: Optional[redis.Redis] = None

    # ─── Types ─────────────────────────────────────────────
    TYPES = {
        "ip": "whitelist:ip",
        "user": "whitelist:user",
        "api_key": "whitelist:api_key",
        "path": "whitelist:path",
    }

    # ─── Default Trusted IPs ──────────────────────────────
    DEFAULT_WHITELISTED_IPS = [
        "127.0.0.1",
        "::1",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
    ]

    # ─── Default Whitelisted Paths ────────────────────────
    DEFAULT_WHITELISTED_PATHS = [
        "/health",
        "/api/v1/health",
        "/docs",
        "/redoc",
        "/openapi.json",
        "/favicon.ico",
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
                logger.error("whitelist_redis_init_failed", error=str(e))
                return None
        return cls._redis_client

    @classmethod
    def _key(cls, whitelist_type: str) -> str:
        """بتبني مفتاح Redis."""
        return cls.TYPES.get(whitelist_type, f"whitelist:{whitelist_type}")

    # ─── Add ──────────────────────────────────────────────

    @classmethod
    async def add(
        cls,
        value: str,
        whitelist_type: str = "ip",
        ttl: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
        reason: str = "",
    ) -> bool:
        """
        بيضيف entry للـ whitelist.

        Args:
            value: القيمة (IP, user_id, path, ...)
            whitelist_type: ip / user / api_key / path
            ttl: مدة (ثواني) - None = دائم
            metadata: بيانات إضافية
            reason: سبب الإضافة

        Returns:
            True لو نجح
        """
        if whitelist_type not in cls.TYPES:
            logger.warning("whitelist_invalid_type", type=whitelist_type)
            return False

        client = cls.get_client()
        if not client:
            return False

        try:
            key = cls._key(whitelist_type)

            # جهز الـ value مع metadata
            entry = {
                "value": value,
                "added_at": time.time(),
                "reason": reason,
                "metadata": metadata or {},
            }

            entry_json = json.dumps(entry)

            # لو TTL محدد → temporary
            if ttl:
                entry_key = f"{key}:entry:{value}"
                await client.setex(entry_key, ttl, entry_json)
                await client.sadd(key, value)
                # نخلي الـ set يدوم أطول من الـ TTL
                await client.expire(key, ttl + 60)
            else:
                # دائم
                entry_key = f"{key}:entry:{value}"
                await client.set(entry_key, entry_json)
                await client.sadd(key, value)

            logger.info(
                "whitelist_added",
                type=whitelist_type,
                value=value[:50],
                ttl=ttl,
                reason=reason[:100],
            )

            return True

        except Exception as e:
            logger.error("whitelist_add_failed", error=str(e))
            return False

    # ─── Remove ───────────────────────────────────────────

    @classmethod
    async def remove(
        cls,
        value: str,
        whitelist_type: str = "ip",
    ) -> bool:
        """بيشيل entry من الـ whitelist."""
        client = cls.get_client()
        if not client:
            return False

        try:
            key = cls._key(whitelist_type)
            entry_key = f"{key}:entry:{value}"

            await client.srem(key, value)
            await client.delete(entry_key)

            logger.info(
                "whitelist_removed",
                type=whitelist_type,
                value=value[:50],
            )
            return True

        except Exception as e:
            logger.error("whitelist_remove_failed", error=str(e))
            return False

    # ─── Check ────────────────────────────────────────────

    @classmethod
    async def is_whitelisted(
        cls,
        value: str,
        whitelist_type: str = "ip",
    ) -> bool:
        """
        بيفحص لو القيمة في الـ whitelist.

        Args:
            value: القيمة
            whitelist_type: نوع الـ whitelist

        Returns:
            True لو موجودة
        """
        client = cls.get_client()
        if not client:
            return False

        try:
            key = cls._key(whitelist_type)

            # 1. فحص مباشر في الـ Set
            if await client.sismember(key, value):
                return True

            # 2. لو IP → فحص CIDR
            if whitelist_type == "ip":
                return await cls._check_ip_cidr(value)

            return False

        except Exception as e:
            logger.error("whitelist_check_failed", error=str(e))
            return False

    @classmethod
    async def _check_ip_cidr(cls, ip: str) -> bool:
        """
        بيفحص لو الـ IP في أي CIDR range في الـ whitelist.
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
        except (ValueError, TypeError):
            return False

        client = cls.get_client()
        if not client:
            return False

        try:
            key = cls._key("ip")
            all_values = await client.smembers(key)

            for entry in all_values:
                # لو CIDR
                if "/" in entry:
                    try:
                        network = ipaddress.ip_network(entry, strict=False)
                        if ip_obj in network:
                            return True
                    except (ValueError, TypeError):
                        continue

            return False

        except Exception as e:
            logger.error("whitelist_cidr_check_failed", error=str(e))
            return False

    # ─── Get All ──────────────────────────────────────────

    @classmethod
    async def get_all(
        cls,
        whitelist_type: str = "ip",
    ) -> List[Dict[str, Any]]:
        """
        بترجع كل الـ entries في whitelist.

        Returns:
            list of dicts
        """
        client = cls.get_client()
        if not client:
            return []

        try:
            key = cls._key(whitelist_type)
            values = await client.smembers(key)

            result = []
            for value in values:
                entry_key = f"{key}:entry:{value}"
                entry_json = await client.get(entry_key)

                if entry_json:
                    try:
                        entry = json.loads(entry_json)
                        entry["has_ttl"] = True
                        result.append(entry)
                    except json.JSONDecodeError:
                        continue
                else:
                    # دائم (مفيش entry_key)
                    result.append({
                        "value": value,
                        "added_at": None,
                        "reason": "",
                        "metadata": {},
                        "has_ttl": False,
                    })

            # رتب حسب وقت الإضافة
            result.sort(
                key=lambda x: x.get("added_at") or 0,
                reverse=True,
            )

            return result

        except Exception as e:
            logger.error("whitelist_get_all_failed", error=str(e))
            return []

    # ─── Clear ────────────────────────────────────────────

    @classmethod
    async def clear(
        cls,
        whitelist_type: Optional[str] = None,
    ) -> None:
        """
        بيمسح whitelist أو كل الـ whitelists.
        """
        client = cls.get_client()
        if not client:
            return

        try:
            if whitelist_type:
                key = cls._key(whitelist_type)
                # امسح الـ set
                values = await client.smembers(key)
                await client.delete(key)
                # امسح الـ entries
                for value in values:
                    await client.delete(f"{key}:entry:{value}")

                logger.info("whitelist_cleared", type=whitelist_type)
            else:
                # امسح كل حاجة
                for whitelist_type in cls.TYPES:
                    await cls.clear(whitelist_type)

                logger.info("whitelist_cleared_all")

        except Exception as e:
            logger.error("whitelist_clear_failed", error=str(e))

    # ─── Bulk Add ─────────────────────────────────────────

    @classmethod
    async def add_bulk(
        cls,
        values: List[str],
        whitelist_type: str = "ip",
        ttl: Optional[int] = None,
        reason: str = "",
    ) -> int:
        """
        بيضيف قائمة قيم.

        Returns:
            عدد القيم اللي اتضافت
        """
        count = 0
        for value in values:
            success = await cls.add(
                value=value,
                whitelist_type=whitelist_type,
                ttl=ttl,
                reason=reason,
            )
            if success:
                count += 1

        return count

    # ─── Initialize Defaults ──────────────────────────────

    @classmethod
    async def initialize_defaults(cls) -> Dict[str, int]:
        """
        بضيف الـ default whitelists.

        Returns:
            dict فيه عدد الـ entries لكل نوع
        """
        result = {}

        # IPs
        count = await cls.add_bulk(
            values=cls.DEFAULT_WHITELISTED_IPS,
            whitelist_type="ip",
            reason="default_whitelist",
        )
        result["ip"] = count

        # Paths
        count = await cls.add_bulk(
            values=cls.DEFAULT_WHITELISTED_PATHS,
            whitelist_type="path",
            reason="default_whitelist",
        )
        result["path"] = count

        logger.info("whitelist_defaults_initialized", **result)
        return result

    # ─── Stats ────────────────────────────────────────────

    @classmethod
    async def get_stats(cls) -> Dict[str, int]:
        """بترجع عدد الـ entries في كل whitelist."""
        client = cls.get_client()
        if not client:
            return {}

        try:
            stats = {}
            for whitelist_type in cls.TYPES:
                key = cls._key(whitelist_type)
                count = await client.scard(key)
                stats[whitelist_type] = count

            return stats

        except Exception as e:
            logger.error("whitelist_stats_failed", error=str(e))
            return {}

    # ─── Bulk Check ───────────────────────────────────────

    @classmethod
    async def is_any_whitelisted(
        cls,
        checks: List[Dict[str, str]],
    ) -> bool:
        """
        بيفحص قائمة checks.

        Args:
            checks: list of {"value": ..., "type": ...}

        Returns:
            True لو أي واحدة whitelisted
        """
        for check in checks:
            value = check.get("value", "")
            whitelist_type = check.get("type", "ip")

            if value and await cls.is_whitelisted(value, whitelist_type):
                return True

        return False

    # ─── Close ────────────────────────────────────────────

    @classmethod
    async def close(cls) -> None:
        """بتقفل Redis."""
        if cls._redis_client:
            await cls._redis_client.close()
            cls._redis_client = None