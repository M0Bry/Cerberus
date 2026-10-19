"""
Graduated Response — Tiered response system based on offense history.

بيوفر:
- Multi-tier response system (7 tiers)
- Offense tracking per entity (IP/user/session)
- Time decay (auto-recovery بعد فترة نظيفة)
- Escalation بين الـ tiers
- Integration with progressive_blocker
- Redis-backed
- Per-tier configuration
- Audit trail

الفكرة:
- بدل ما نحظر من أول مخالفة، بنستخدم نظام متدرج
- كل مخالفة بترفع الـ tier
- بعد فترة نظيفة، الـ tier بينزل (decay)
- كل tier له action مختلف

الـ Tiers:
0. clean (0 offenses) → allow
1. warning (1 offense) → warn + log
2. throttle (2 offenses) → slow requests
3. short_block (3 offenses) → 5 min block
4. medium_block (4 offenses) → 1 hour block
5. long_block (5 offenses) → 24 hour block
6. extended_block (6+ offenses) → 7 day block

الاستخدام:
- defense_middleware.py
- auto_mitigation.py
- progressive_blocker.py
- abuse_detector.py
"""

import json
import math
import time
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import redis.asyncio as redis
import structlog

from app.core.config import settings

logger = structlog.get_logger()


class ResponseTier(int, Enum):
    """مستويات الـ graduated response."""
    CLEAN = 0
    WARNING = 1
    THROTTLE = 2
    SHORT_BLOCK = 3
    MEDIUM_BLOCK = 4
    LONG_BLOCK = 5
    EXTENDED_BLOCK = 6


class GraduatedResponse:
    """
    Graduated Response System.

    الفكرة:
    - نتتبع offenses لكل entity
    - نحسب الـ tier الحالي
    - نرجع الـ action المناسب
    - time decay بيقلل الـ offenses مع الوقت
    """

    _redis_client: Optional[redis.Redis] = None

    # ─── Config ────────────────────────────────────────────
    HISTORY_TTL = 86400 * 30     # 30 يوم
    OFFENSE_TTL = 86400 * 7      # 7 أيام
    DECAY_INTERVAL = 86400       # كل 24 ساعة ينزل offense واحد
    MAX_OFFENSES = 100           # حد أقصى للتخزين

    # ─── Tier Configuration ───────────────────────────────
    # كل tier: (min_offenses, max_offenses, action, duration_seconds)
    TIERS = {
        ResponseTier.CLEAN: {
            "min": 0, "max": 0,
            "action": "allow",
            "duration": 0,
            "name": "clean",
            "description": "Normal access",
        },
        ResponseTier.WARNING: {
            "min": 1, "max": 1,
            "action": "warn",
            "duration": 0,
            "name": "warning",
            "description": "Warning + increased logging",
        },
        ResponseTier.THROTTLE: {
            "min": 2, "max": 2,
            "action": "throttle",
            "duration": 300,          # 5 دقائق throttle
            "name": "throttle",
            "description": "Rate limiting applied",
        },
        ResponseTier.SHORT_BLOCK: {
            "min": 3, "max": 3,
            "action": "block",
            "duration": 300,          # 5 دقائق
            "name": "short_block",
            "description": "Short temporary block",
        },
        ResponseTier.MEDIUM_BLOCK: {
            "min": 4, "max": 4,
            "action": "block",
            "duration": 3600,         # ساعة
            "name": "medium_block",
            "description": "Medium temporary block",
        },
        ResponseTier.LONG_BLOCK: {
            "min": 5, "max": 5,
            "action": "block",
            "duration": 86400,        # يوم
            "name": "long_block",
            "description": "Long temporary block",
        },
        ResponseTier.EXTENDED_BLOCK: {
            "min": 6, "max": 999,
            "action": "block",
            "duration": 86400 * 7,    # أسبوع
            "name": "extended_block",
            "description": "Extended block (manual review required)",
        },
    }

    # ─── Redis Keys ───────────────────────────────────────
    OFFENSES_KEY_PREFIX = "gr:offenses:"
    TIER_KEY_PREFIX = "gr:tier:"
    HISTORY_KEY_PREFIX = "gr:history:"
    DECAY_KEY_PREFIX = "gr:decay:"

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
                logger.error("graduated_response_redis_init_failed", error=str(e))
                return None
        return cls._redis_client

    @staticmethod
    def _offenses_key(entity_type: str, entity_value: str) -> str:
        return f"{GraduatedResponse.OFFENSES_KEY_PREFIX}{entity_type}:{entity_value}"

    @staticmethod
    def _tier_key(entity_type: str, entity_value: str) -> str:
        return f"{GraduatedResponse.TIER_KEY_PREFIX}{entity_type}:{entity_value}"

    @staticmethod
    def _history_key(entity_type: str, entity_value: str) -> str:
        return f"{GraduatedResponse.HISTORY_KEY_PREFIX}{entity_type}:{entity_value}"

    @staticmethod
    def _decay_key(entity_type: str, entity_value: str) -> str:
        return f"{GraduatedResponse.DECAY_KEY_PREFIX}{entity_type}:{entity_value}"

    @classmethod
    def _tier_from_offenses(cls, offenses: int) -> ResponseTier:
        """بيحدد الـ tier من عدد الـ offenses."""
        for tier, config in cls.TIERS.items():
            if config["min"] <= offenses <= config["max"]:
                return tier
        return ResponseTier.EXTENDED_BLOCK

    @classmethod
    def _get_tier_info(cls, tier: ResponseTier) -> Dict[str, Any]:
        """بيرجع معلومات الـ tier."""
        return cls.TIERS.get(tier, cls.TIERS[ResponseTier.CLEAN])

    # ═══════════════════════════════════════════════════════
    #  Offense Recording
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def record_offense(
        cls,
        entity_type: str,
        entity_value: str,
        *,
        reason: str = "unknown",
        severity: str = "medium",
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        بيسجل مخالفة جديدة.

        Args:
            entity_type: نوع الكيان
            entity_value: قيمة الكيان
            reason: سبب المخالفة
            severity: level (low/medium/high/critical)
            details: تفاصيل إضافية

        Returns:
            dict فيه:
            - offenses: العدد الحالي
            - tier: المستوى الحالي
            - action: الإجراء المطلوب
            - duration: المدة (لو block)
            - escalated: هل زاد الـ tier؟
        """
        client = cls.get_client()
        if not client:
            return {"success": False, "error": "redis_unavailable"}

        try:
            if not entity_type or not entity_value:
                return {"success": False, "error": "missing_entity_info"}

            now = time.time()

            # ─── 1. استرجع الـ offenses الحالي ───
            offenses_key = cls._offenses_key(entity_type, entity_value)
            old_offenses = int(await client.get(offenses_key) or 0)

            # ─── 2. زوّد العدد ───
            new_offenses = old_offenses + 1

            # حد أقصى
            if new_offenses > cls.MAX_OFFENSES:
                new_offenses = cls.MAX_OFFENSES

            await client.set(
                offenses_key,
                str(new_offenses),
                ex=cls.OFFENSE_TTL,
            )

            # ─── 3. سجل في history ───
            history_key = cls._history_key(entity_type, entity_value)
            entry = {
                "timestamp": now,
                "reason": reason,
                "severity": severity,
                "details": details or {},
                "offense_number": new_offenses,
            }
            await client.lpush(history_key, json.dumps(entry))
            await client.ltrim(history_key, 0, 99)  # آخر 100
            await client.expire(history_key, cls.HISTORY_TTL)

            # ─── 4. احسب الـ tier الجديد ───
            old_tier = cls._tier_from_offenses(old_offenses)
            new_tier = cls._tier_from_offenses(new_offenses)

            # ─── 5. سجل الـ tier ───
            tier_key = cls._tier_key(entity_type, entity_value)
            tier_info = cls._get_tier_info(new_tier)
            await client.set(
                tier_key,
                json.dumps({
                    "tier": new_tier.value,
                    "name": tier_info["name"],
                    "action": tier_info["action"],
                    "duration": tier_info["duration"],
                    "updated_at": now,
                }),
                ex=cls.HISTORY_TTL,
            )

            # ─── 6. Reset decay timer ───
            decay_key = cls._decay_key(entity_type, entity_value)
            await client.set(decay_key, str(now), ex=cls.DECAY_INTERVAL * 2)

            # ─── 7. escalated? ───
            escalated = new_tier.value > old_tier.value

            if escalated:
                logger.warning(
                    "graduated_response_escalated",
                    entity=f"{entity_type}:{entity_value}",
                    old_tier=old_tier.name,
                    new_tier=new_tier.name,
                    offenses=new_offenses,
                    action=tier_info["action"],
                    duration=tier_info["duration"],
                )
            else:
                logger.info(
                    "graduated_response_offense",
                    entity=f"{entity_type}:{entity_value}",
                    offenses=new_offenses,
                    tier=new_tier.name,
                )

            return {
                "success": True,
                "entity": f"{entity_type}:{entity_value}",
                "offenses": new_offenses,
                "old_offenses": old_offenses,
                "tier": new_tier.value,
                "tier_name": tier_info["name"],
                "action": tier_info["action"],
                "duration": tier_info["duration"],
                "description": tier_info["description"],
                "escalated": escalated,
                "old_tier": old_tier.value if escalated else None,
                "recorded_at": now,
            }

        except Exception as e:
            logger.error("graduated_response_record_failed", error=str(e))
            return {"success": False, "error": str(e)}

    # ═══════════════════════════════════════════════════════
    #  Get Current State
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def get_state(
        cls,
        entity_type: str,
        entity_value: str,
    ) -> Dict[str, Any]:
        """
        بيرجع الحالة الحالية للكيان.

        Returns:
            dict فيه: offenses, tier, action, duration
        """
        client = cls.get_client()
        if not client:
            return {"success": False, "error": "redis_unavailable"}

        try:
            offenses_key = cls._offenses_key(entity_type, entity_value)
            offenses = int(await client.get(offenses_key) or 0)

            tier = cls._tier_from_offenses(offenses)
            tier_info = cls._get_tier_info(tier)

            return {
                "success": True,
                "entity": f"{entity_type}:{entity_value}",
                "offenses": offenses,
                "tier": tier.value,
                "tier_name": tier_info["name"],
                "action": tier_info["action"],
                "duration": tier_info["duration"],
                "description": tier_info["description"],
                "is_blocked": tier_info["action"] == "block",
            }

        except Exception as e:
            logger.error("graduated_response_get_state_failed", error=str(e))
            return {"success": False, "error": str(e)}

    @classmethod
    async def get_response(
        cls,
        entity_type: str,
        entity_value: str,
    ) -> Dict[str, Any]:
        """
        بيرجع الـ response المناسب للكيان (بعد تطبيق decay).

        Returns:
            dict فيه: action, duration, tier
        """
        # طبّق decay الأول
        await cls.apply_decay(entity_type, entity_value)

        return await cls.get_state(entity_type, entity_value)

    # ═══════════════════════════════════════════════════════
    #  Decay (Auto-Recovery)
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def apply_decay(
        cls,
        entity_type: str,
        entity_value: str,
    ) -> Dict[str, Any]:
        """
        بيطبّق الـ decay — يقلل الـ offenses بناءً على الوقت.

        كل DECAY_INTERVAL (24 ساعة) بدون مخالفة → -1 offense
        """
        client = cls.get_client()
        if not client:
            return {"success": False, "error": "redis_unavailable"}

        try:
            decay_key = cls._decay_key(entity_type, entity_value)
            last_offense_str = await client.get(decay_key)

            if not last_offense_str:
                return {"success": True, "decayed": 0}

            last_offense = float(last_offense_str)
            now = time.time()
            elapsed = now - last_offense

            if elapsed < cls.DECAY_INTERVAL:
                return {
                    "success": True,
                    "decayed": 0,
                    "next_decay_in_seconds": int(cls.DECAY_INTERVAL - elapsed),
                }

            # عدد الـ intervals اللي عدت
            intervals = int(elapsed // cls.DECAY_INTERVAL)

            offenses_key = cls._offenses_key(entity_type, entity_value)
            current_offenses = int(await client.get(offenses_key) or 0)

            if current_offenses == 0:
                return {"success": True, "decayed": 0}

            # قلل offenses
            new_offenses = max(current_offenses - intervals, 0)

            if new_offenses == 0:
                # امسح المفتاح
                await client.delete(offenses_key)
                await client.delete(decay_key)
            else:
                await client.set(
                    offenses_key,
                    str(new_offenses),
                    ex=cls.OFFENSE_TTL,
                )
                # حدّث الـ decay key للوقت الحالي + الباقي
                remaining = elapsed - (intervals * cls.DECAY_INTERVAL)
                await client.set(
                    decay_key,
                    str(now - remaining),
                    ex=cls.DECAY_INTERVAL * 2,
                )

            decayed = current_offenses - new_offenses

            if decayed > 0:
                logger.info(
                    "graduated_response_decay",
                    entity=f"{entity_type}:{entity_value}",
                    old_offenses=current_offenses,
                    new_offenses=new_offenses,
                    decayed=decayed,
                )

            return {
                "success": True,
                "decayed": decayed,
                "old_offenses": current_offenses,
                "new_offenses": new_offenses,
            }

        except Exception as e:
            logger.error("graduated_response_decay_failed", error=str(e))
            return {"success": False, "error": str(e)}

    # ═══════════════════════════════════════════════════════
    #  Tier Management
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def escalate(
        cls,
        entity_type: str,
        entity_value: str,
        *,
        by: int = 1,
    ) -> Dict[str, Any]:
        """
        بيرفع الـ tier يدوياً (بدون offense).

        مفيد للـ admin actions.
        """
        client = cls.get_client()
        if not client:
            return {"success": False, "error": "redis_unavailable"}

        try:
            offenses_key = cls._offenses_key(entity_type, entity_value)
            current = int(await client.get(offenses_key) or 0)

            new_offenses = current + by
            await client.set(
                offenses_key,
                str(new_offenses),
                ex=cls.OFFENSE_TTL,
            )

            # حدّث decay timer
            decay_key = cls._decay_key(entity_type, entity_value)
            await client.set(
                decay_key,
                str(time.time()),
                ex=cls.DECAY_INTERVAL * 2,
            )

            tier = cls._tier_from_offenses(new_offenses)
            tier_info = cls._get_tier_info(tier)

            logger.info(
                "graduated_response_manual_escalate",
                entity=f"{entity_type}:{entity_value}",
                old_offenses=current,
                new_offenses=new_offenses,
                tier=tier.name,
            )

            return {
                "success": True,
                "offenses": new_offenses,
                "tier": tier.value,
                "tier_name": tier_info["name"],
                "action": tier_info["action"],
                "duration": tier_info["duration"],
            }

        except Exception as e:
            logger.error("graduated_response_escalate_failed", error=str(e))
            return {"success": False, "error": str(e)}

    @classmethod
    async def reset(
        cls,
        entity_type: str,
        entity_value: str,
    ) -> Dict[str, Any]:
        """بيصفّر الـ offenses (full reset)."""
        client = cls.get_client()
        if not client:
            return {"success": False, "error": "redis_unavailable"}

        try:
            keys = [
                cls._offenses_key(entity_type, entity_value),
                cls._tier_key(entity_type, entity_value),
                cls._decay_key(entity_type, entity_value),
            ]
            await client.delete(*keys)

            logger.info(
                "graduated_response_reset",
                entity=f"{entity_type}:{entity_value}",
            )

            return {
                "success": True,
                "entity": f"{entity_type}:{entity_value}",
            }

        except Exception as e:
            logger.error("graduated_response_reset_failed", error=str(e))
            return {"success": False, "error": str(e)}

    # ═══════════════════════════════════════════════════════
    #  History
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def get_history(
        cls,
        entity_type: str,
        entity_value: str,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """بيرجع تاريخ المخالفات."""
        client = cls.get_client()
        if not client:
            return []

        try:
            history_key = cls._history_key(entity_type, entity_value)
            raw_list = await client.lrange(history_key, 0, limit - 1)

            history = []
            for raw in raw_list:
                try:
                    history.append(json.loads(raw))
                except json.JSONDecodeError:
                    continue

            return history

        except Exception as e:
            logger.error("graduated_response_history_failed", error=str(e))
            return []

    # ═══════════════════════════════════════════════════════
    #  Stats
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def get_stats(cls) -> Dict[str, Any]:
        """بيرجع إحصائيات الـ graduated response."""
        client = cls.get_client()
        if not client:
            return {"success": False, "error": "redis_unavailable"}

        try:
            tier_counts: Dict[str, int] = {t.name: 0 for t in ResponseTier}
            total_entities = 0
            total_offenses = 0

            cursor = 0
            while True:
                cursor, keys = await client.scan(
                    cursor=cursor,
                    match=f"{cls.OFFENSES_KEY_PREFIX}*",
                    count=100,
                )
                for key in keys:
                    total_entities += 1
                    val = int(await client.get(key) or 0)
                    total_offenses += val

                    tier = cls._tier_from_offenses(val)
                    tier_counts[tier.name] += 1

                if cursor == 0:
                    break

            return {
                "success": True,
                "total_entities": total_entities,
                "total_offenses": total_offenses,
                "tier_distribution": tier_counts,
            }

        except Exception as e:
            logger.error("graduated_response_stats_failed", error=str(e))
            return {"success": False, "error": str(e)}

    # ═══════════════════════════════════════════════════════
    #  Utilities
    # ═══════════════════════════════════════════════════════

    @classmethod
    def get_tier_config(cls, tier: ResponseTier) -> Dict[str, Any]:
        """بيرجع config tier معين."""
        return cls._get_tier_info(tier)

    @classmethod
    def get_all_tiers(cls) -> Dict[int, Dict[str, Any]]:
        """بيرجع config كل الـ tiers."""
        return {
            tier.value: {
                **config,
                "tier_name": tier.name,
            }
            for tier, config in cls.TIERS.items()
        }

    @classmethod
    async def clear_all(cls) -> None:
        """بيمسح كل البيانات."""
        client = cls.get_client()
        if not client:
            return

        try:
            cursor = 0
            while True:
                cursor, keys = await client.scan(
                    cursor=cursor,
                    match="gr:*",
                    count=100,
                )
                if keys:
                    await client.delete(*keys)
                if cursor == 0:
                    break

            logger.info("graduated_response_all_cleared")
        except Exception as e:
            logger.error("graduated_response_clear_all_failed", error=str(e))

    @classmethod
    async def close(cls) -> None:
        """بتقفل Redis."""
        if cls._redis_client:
            await cls._redis_client.close()
            cls._redis_client = None


# ─── Standalone functions ─────────────────────────────

async def record_offense(
    entity_type: str,
    entity_value: str,
    **kwargs,
) -> Dict[str, Any]:
    """Shortcut for GraduatedResponse.record_offense."""
    return await GraduatedResponse.record_offense(
        entity_type, entity_value, **kwargs,
    )


async def get_response(
    entity_type: str,
    entity_value: str,
) -> Dict[str, Any]:
    """Shortcut for GraduatedResponse.get_response."""
    return await GraduatedResponse.get_response(entity_type, entity_value)


async def reset(
    entity_type: str,
    entity_value: str,
) -> Dict[str, Any]:
    """Shortcut for GraduatedResponse.reset."""
    return await GraduatedResponse.reset(entity_type, entity_value)