"""
Progressive Blocker — Progressive banning based on offense history.

بيوفر:
- Progressive ban durations (5m → 30m → 2h → 12h → 3d → 1w → 30d)
- Offense tracking (Redis-backed)
- Per-IP, Per-User blocking
- Auto-reset after good behavior
- Whitelist support
- Manual override

الفكرة:
- كل IP عنده offense_count
- كل offense بيضاعف المدة
- بعد فترة معينة، الـ count بيتصفر (إذا مفيش مخالفات)

الاستخدام:
- Auto-mitigation
- Abuse prevention
- Fair usage enforcement
"""

import time
from typing import Any, Dict, List, Optional, Tuple

import redis.asyncio as redis
import structlog

from app.core.config import settings

logger = structlog.get_logger()


class ProgressiveBlocker:
    """
    Progressive Blocker.

    الفكرة:
    - 7 مستويات من الحظر
    - كل offense بياخد مدة أطول
    - الـ count بيتصفر بعد فترة نظافة
    """

    _redis_client: Optional[redis.Redis] = None

    # ─── Ban Durations (بالثواني) ─────────────────────────
    BAN_DURATIONS = [
        300,        # 1: 5 دقايق
        1800,       # 2: 30 دقيقة
        7200,       # 3: 2 ساعات
        43200,      # 4: 12 ساعة
        259200,     # 5: 3 أيام
        604800,     # 6: أسبوع
        2592000,    # 7+: 30 يوم
    ]

    # ─── Config ────────────────────────────────────────────
    OFFENSE_RESET_TTL = 86400 * 7   # 7 أيام (بعدها الـ count يتصفر)
    BLOCK_KEY_TTL = 2592000          # 30 يوم (أقصى مدة)

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
                logger.error("progressive_blocker_redis_init_failed", error=str(e))
                return None
        return cls._redis_client

    @staticmethod
    def _offense_key(identifier: str, scope: str = "ip") -> str:
        """مفتاح offense count."""
        return f"progressive:offenses:{scope}:{identifier}"

    @staticmethod
    def _blocked_key(identifier: str, scope: str = "ip") -> str:
        """مفتاح blocked status."""
        return f"progressive:blocked:{scope}:{identifier}"

    @staticmethod
    def _history_key(identifier: str, scope: str = "ip") -> str:
        """مفتاح سجل الحظر."""
        return f"progressive:history:{scope}:{identifier}"

    @staticmethod
    def _whitelist_key(identifier: str, scope: str = "ip") -> str:
        """مفتاح whitelist."""
        return f"progressive:whitelist:{scope}:{identifier}"

    # ─── Duration Calculation ─────────────────────────────

    @classmethod
    def get_ban_duration(cls, offense_count: int) -> int:
        """
        بترجع مدة الحظر حسب عدد المخالفات.

        Args:
            offense_count: عدد المخالفات (1-based)

        Returns:
            المدة بالثواني
        """
        if offense_count <= 0:
            return 0

        # لو أكتر من عدد المستويات → استخدم أقصى مدة
        index = min(offense_count - 1, len(cls.BAN_DURATIONS) - 1)
        return cls.BAN_DURATIONS[index]

    @classmethod
    def format_duration(cls, seconds: int) -> str:
        """بتحول الثواني لنص مفهوم."""
        if seconds < 60:
            return f"{seconds}s"
        elif seconds < 3600:
            return f"{seconds // 60}m"
        elif seconds < 86400:
            return f"{seconds // 3600}h"
        else:
            return f"{seconds // 86400}d"

    # ─── Offense Management ───────────────────────────────

    @classmethod
    async def record_offense(
        cls,
        identifier: str,
        reason: str = "",
        scope: str = "ip",
    ) -> Dict[str, Any]:
        """
        بيسجل مخالفة جديدة وبيحظر الـ identifier.

        Args:
            identifier: IP أو user_id
            reason: سبب المخالفة
            scope: ip / user

        Returns:
            dict فيه:
            - offense_count: عدد المخالفات الحالي
            - ban_duration: مدة الحظر الحالية
            - ban_duration_human: نص مفهوم
            - blocked_until: وقت انتهاء الحظر
            - is_whitelisted: هل في whitelist
        """
        client = cls.get_client()
        if not client:
            return cls._empty_result(identifier, scope)

        try:
            # 1. فحص الـ whitelist
            is_whitelisted = await cls.is_whitelisted(identifier, scope)
            if is_whitelisted:
                logger.info(
                    "progressive_blocker_whitelisted",
                    identifier=identifier,
                    scope=scope,
                )
                return {
                    "identifier": identifier,
                    "scope": scope,
                    "offense_count": 0,
                    "ban_duration": 0,
                    "ban_duration_human": "0s",
                    "blocked_until": 0,
                    "is_whitelisted": True,
                    "message": "Identifier is whitelisted, no ban applied",
                }

            # 2. زود الـ offense count
            offense_key = cls._offense_key(identifier, scope)
            offense_count = await client.incr(offense_key)

            # جدد الـ TTL
            await client.expire(offense_key, cls.OFFENSE_RESET_TTL)

            # 3. احسب المدة
            duration = cls.get_ban_duration(offense_count)
            blocked_until = time.time() + duration

            # 4. سجل الحظر
            blocked_key = cls._blocked_key(identifier, scope)
            await client.setex(
                blocked_key,
                duration,
                str(blocked_until),
            )

            # 5. سجل في الـ history
            history_key = cls._history_key(identifier, scope)
            history_entry = f"{time.time()}:{offense_count}:{duration}:{reason[:100]}"
            await client.lpush(history_key, history_entry)
            await client.ltrim(history_key, 0, 49)  # آخر 50
            await client.expire(history_key, cls.OFFENSE_RESET_TTL)

            logger.warning(
                "progressive_ban_applied",
                identifier=identifier,
                scope=scope,
                offense_count=offense_count,
                duration=duration,
                duration_human=cls.format_duration(duration),
                reason=reason[:100],
            )

            return {
                "identifier": identifier,
                "scope": scope,
                "offense_count": offense_count,
                "ban_duration": duration,
                "ban_duration_human": cls.format_duration(duration),
                "blocked_until": blocked_until,
                "is_whitelisted": False,
                "message": f"Banned for {cls.format_duration(duration)} (offense #{offense_count})",
            }

        except Exception as e:
            logger.error("progressive_blocker_record_failed", error=str(e))
            return cls._empty_result(identifier, scope)

    @classmethod
    def _empty_result(cls, identifier: str, scope: str) -> Dict[str, Any]:
        """نتيجة فاضية."""
        return {
            "identifier": identifier,
            "scope": scope,
            "offense_count": 0,
            "ban_duration": 0,
            "ban_duration_human": "0s",
            "blocked_until": 0,
            "is_whitelisted": False,
            "message": "Error occurred",
        }

    # ─── Block Status ─────────────────────────────────────

    @classmethod
    async def is_blocked(
        cls,
        identifier: str,
        scope: str = "ip",
    ) -> bool:
        """بيفحص لو الـ identifier محظور."""
        client = cls.get_client()
        if not client:
            return False

        try:
            # فحص whitelist أولاً
            if await cls.is_whitelisted(identifier, scope):
                return False

            blocked_key = cls._blocked_key(identifier, scope)
            exists = await client.exists(blocked_key)
            return exists > 0

        except Exception as e:
            logger.error("progressive_blocker_is_blocked_failed", error=str(e))
            return False

    @classmethod
    async def get_block_info(
        cls,
        identifier: str,
        scope: str = "ip",
    ) -> Dict[str, Any]:
        """
        بترجع معلومات الحظر.

        Returns:
            dict فيه:
            - is_blocked: bool
            - blocked_until: وقت انتهاء الحظر
            - seconds_remaining: الثواني المتبقية
            - offense_count: عدد المخالفات
            - reason: سبب آخر مخالفة
        """
        client = cls.get_client()
        if not client:
            return {"is_blocked": False}

        try:
            # 1. offense count
            offense_key = cls._offense_key(identifier, scope)
            offense_count_str = await client.get(offense_key)
            offense_count = int(offense_count_str) if offense_count_str else 0

            # 2. blocked status
            blocked_key = cls._blocked_key(identifier, scope)
            blocked_until_str = await client.get(blocked_key)

            if not blocked_until_str:
                return {
                    "identifier": identifier,
                    "scope": scope,
                    "is_blocked": False,
                    "offense_count": offense_count,
                    "blocked_until": 0,
                    "seconds_remaining": 0,
                }

            blocked_until = float(blocked_until_str)
            now = time.time()
            seconds_remaining = max(0, int(blocked_until - now))

            # 3. reason من الـ history
            history_key = cls._history_key(identifier, scope)
            history = await client.lrange(history_key, 0, 0)
            reason = ""
            if history:
                try:
                    parts = history[0].split(":", 3)
                    if len(parts) >= 4:
                        reason = parts[3]
                except (ValueError, IndexError):
                    pass

            return {
                "identifier": identifier,
                "scope": scope,
                "is_blocked": seconds_remaining > 0,
                "offense_count": offense_count,
                "blocked_until": blocked_until,
                "seconds_remaining": seconds_remaining,
                "duration_human": cls.format_duration(seconds_remaining),
                "reason": reason,
            }

        except Exception as e:
            logger.error("progressive_blocker_get_info_failed", error=str(e))
            return {"is_blocked": False}

    # ─── Unblock ──────────────────────────────────────────

    @classmethod
    async def unblock(
        cls,
        identifier: str,
        scope: str = "ip",
        reset_offenses: bool = False,
    ) -> bool:
        """
        بفك الحظر.

        Args:
            identifier: IP أو user_id
            scope: ip / user
            reset_offenses: لو True، يصفر عدد المخالفات

        Returns:
            True لو نجح
        """
        client = cls.get_client()
        if not client:
            return False

        try:
            # 1. امسح الـ block
            blocked_key = cls._blocked_key(identifier, scope)
            await client.delete(blocked_key)

            # 2. امسح الـ offenses لو مطلوب
            if reset_offenses:
                offense_key = cls._offense_key(identifier, scope)
                await client.delete(offense_key)

            logger.info(
                "progressive_unblocked",
                identifier=identifier,
                scope=scope,
                reset_offenses=reset_offenses,
            )
            return True

        except Exception as e:
            logger.error("progressive_blocker_unblock_failed", error=str(e))
            return False

    # ─── Whitelist ────────────────────────────────────────

    @classmethod
    async def add_to_whitelist(
        cls,
        identifier: str,
        scope: str = "ip",
        ttl: Optional[int] = None,
    ) -> bool:
        """
        بيضيف identifier للـ whitelist.

        Args:
            identifier: IP أو user_id
            scope: ip / user
            ttl: مدة الـ whitelist (None = دايم)
        """
        client = cls.get_client()
        if not client:
            return False

        try:
            whitelist_key = cls._whitelist_key(identifier, scope)

            if ttl:
                await client.setex(whitelist_key, ttl, "1")
            else:
                await client.set(whitelist_key, "1")

            # امسح الحظر الحالي
            blocked_key = cls._blocked_key(identifier, scope)
            await client.delete(blocked_key)

            logger.info(
                "progressive_whitelisted",
                identifier=identifier,
                scope=scope,
                ttl=ttl,
            )
            return True

        except Exception as e:
            logger.error("progressive_blocker_whitelist_failed", error=str(e))
            return False

    @classmethod
    async def remove_from_whitelist(
        cls,
        identifier: str,
        scope: str = "ip",
    ) -> bool:
        """بيشيل identifier من الـ whitelist."""
        client = cls.get_client()
        if not client:
            return False

        try:
            whitelist_key = cls._whitelist_key(identifier, scope)
            await client.delete(whitelist_key)
            logger.info(
                "progressive_unwhitelisted",
                identifier=identifier,
                scope=scope,
            )
            return True
        except Exception as e:
            logger.error("progressive_blocker_unwhitelist_failed", error=str(e))
            return False

    @classmethod
    async def is_whitelisted(
        cls,
        identifier: str,
        scope: str = "ip",
    ) -> bool:
        """بيفحص لو الـ identifier في whitelist."""
        client = cls.get_client()
        if not client:
            return False

        try:
            whitelist_key = cls._whitelist_key(identifier, scope)
            return await client.exists(whitelist_key) > 0
        except Exception as e:
            logger.error("progressive_blocker_is_whitelisted_failed", error=str(e))
            return False

    # ─── History ──────────────────────────────────────────

    @classmethod
    async def get_history(
        cls,
        identifier: str,
        scope: str = "ip",
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """
        بترجع سجل الحظر.

        Returns:
            list of dicts
        """
        client = cls.get_client()
        if not client:
            return []

        try:
            history_key = cls._history_key(identifier, scope)
            entries = await client.lrange(history_key, 0, limit - 1)

            result = []
            for entry in entries:
                try:
                    parts = entry.split(":", 3)
                    if len(parts) < 3:
                        continue

                    result.append({
                        "timestamp": float(parts[0]),
                        "offense_count": int(parts[1]),
                        "duration": int(parts[2]),
                        "duration_human": cls.format_duration(int(parts[2])),
                        "reason": parts[3] if len(parts) > 3 else "",
                    })
                except (ValueError, IndexError):
                    continue

            return result

        except Exception as e:
            logger.error("progressive_blocker_history_failed", error=str(e))
            return []

    # ─── Reset ────────────────────────────────────────────

    @classmethod
    async def reset_offenses(
        cls,
        identifier: str,
        scope: str = "ip",
    ) -> bool:
        """
        بيصفر عدد المخالفات بس (بدون فك الحظر).
        """
        client = cls.get_client()
        if not client:
            return False

        try:
            offense_key = cls._offense_key(identifier, scope)
            await client.delete(offense_key)
            logger.info(
                "progressive_offenses_reset",
                identifier=identifier,
                scope=scope,
            )
            return True
        except Exception as e:
            logger.error("progressive_blocker_reset_offenses_failed", error=str(e))
            return False

    # ─── Stats ────────────────────────────────────────────

    @classmethod
    async def get_blocked_ips_count(cls) -> int:
        """بترجع عدد الـ IPs المحظورة حالياً."""
        client = cls.get_client()
        if not client:
            return 0

        try:
            count = 0
            async for key in client.scan_iter(
                match="progressive:blocked:ip:*", count=100
            ):
                count += 1
            return count
        except Exception as e:
            logger.error("progressive_blocker_count_failed", error=str(e))
            return 0

    @classmethod
    async def get_all_blocked_ips(cls) -> List[Dict[str, Any]]:
        """بترجع كل الـ IPs المحظورة."""
        client = cls.get_client()
        if not client:
            return []

        try:
            blocked_list = []
            now = time.time()

            async for key in client.scan_iter(
                match="progressive:blocked:ip:*", count=100
            ):
                # key = "progressive:blocked:ip:1.2.3.4"
                parts = key.split(":")
                if len(parts) < 4:
                    continue

                ip = parts[3]
                blocked_until_str = await client.get(key)

                if blocked_until_str:
                    blocked_until = float(blocked_until_str)
                    seconds_remaining = max(0, int(blocked_until - now))

                    if seconds_remaining > 0:
                        blocked_list.append({
                            "ip": ip,
                            "blocked_until": blocked_until,
                            "seconds_remaining": seconds_remaining,
                            "duration_human": cls.format_duration(seconds_remaining),
                        })

            return sorted(blocked_list, key=lambda x: x["blocked_until"])

        except Exception as e:
            logger.error("progressive_blocker_all_blocked_failed", error=str(e))
            return []

    # ─── Utilities ─────────────────────────────────────────

    @classmethod
    async def clear(
        cls,
        identifier: str,
        scope: str = "ip",
    ) -> None:
        """بيمسح كل بيانات identifier."""
        client = cls.get_client()
        if not client:
            return

        try:
            keys = [
                cls._offense_key(identifier, scope),
                cls._blocked_key(identifier, scope),
                cls._history_key(identifier, scope),
                cls._whitelist_key(identifier, scope),
            ]
            await client.delete(*keys)
            logger.info("progressive_blocker_cleared", identifier=identifier)
        except Exception as e:
            logger.error("progressive_blocker_clear_failed", error=str(e))

    @classmethod
    async def close(cls) -> None:
        """بتقفل Redis."""
        if cls._redis_client:
            await cls._redis_client.close()
            cls._redis_client = None