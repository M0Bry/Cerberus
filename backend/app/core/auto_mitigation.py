"""
Auto Mitigation — Automated threat response & mitigation.

بيوفر:
- Multiple mitigation actions (allow, monitor, challenge, rate_limit, block, temp_block)
- Risk-based decision engine
- Integration with whitelist + progressive_blocker + threat_intel
- Auto-escalation (بيدمج الـ signals)
- Cooldown للـ actions (منع الـ flip-flop)
- Redis-backed
- Audit trail
- Per-IP + per-user mitigation

الفكرة:
- بيدمج output من كل الـ detectors
- بياخد قرار: Allow / Monitor / Challenge / Rate-limit / Block
- القرار بيعتمد على:
  * risk_score
  * signals
  * whitelist status
  * offense history
  * threat intel
- مناسب لـ:
  * Real-time defense
  * Auto-response
  * Incident Response

الاستخدام:
- defense_middleware.py
- defense_service.py
- notifier.py
- attack_chain.py
"""

import json
import time
from enum import Enum
from typing import Any, Dict, List, Optional

import redis.asyncio as redis
import structlog

from app.core.config import settings

logger = structlog.get_logger()


class MitigationAction(str, Enum):
    """أنواع الـ mitigation actions."""
    ALLOW = "allow"                  # اسمح
    MONITOR = "monitor"              # راقب (log بس)
    CHALLENGE = "challenge"          # تحدي (CAPTCHA, OTP)
    RATE_LIMIT = "rate_limit"        # حدد معدل
    TEMP_BLOCK = "temp_block"        # حظر مؤقت
    BLOCK = "block"                  # حظر دائم (يدوي)


class AutoMitigation:
    """
    Auto Mitigation Engine.

    الفكرة:
    - بيدمج output من كل الـ detectors
    - بياخد قرار mitigation
    - بيسجل الـ actions في audit trail
    """

    _redis_client: Optional[redis.Redis] = None

    # ─── Config ────────────────────────────────────────────
    ACTION_TTL = 86400 * 30       # 30 يوم للـ audit
    COOLDOWN_SECONDS = 60         # cooldown بين الـ actions لنفس الـ IP
    MAX_ACTIONS_PER_IP = 100

    # ─── Action Durations (بالثواني) ──────────────────────
    RATE_LIMIT_DURATION = 300      # 5 دقائق
    TEMP_BLOCK_DURATION = 3600     # ساعة
    PERMANENT_BLOCK_FLAG = 0       # flag بس (مش timeout)

    # ─── Risk Thresholds ──────────────────────────────────
    THRESHOLDS = {
        MitigationAction.ALLOW: (0, 29),
        MitigationAction.MONITOR: (30, 49),
        MitigationAction.CHALLENGE: (50, 69),
        MitigationAction.RATE_LIMIT: (70, 79),
        MitigationAction.TEMP_BLOCK: (80, 99),
        MitigationAction.BLOCK: (100, 100),
    }

    # ─── Critical Signals (بترفع الـ action) ─────────────
    CRITICAL_SIGNALS = {
        "sql_injection",
        "rce_attempt",
        "beacon_pattern",
        "c2_traffic",
        "data_exfiltration",
        "ransomware",
        "known_bad_ip",
        "tor_exit",
        "account_takeover",
        "credential_stuffing",
        "bruteforce",
    }

    # ─── High Signals ─────────────────────────────────────
    HIGH_SIGNALS = {
        "malicious_payload",
        "webshell_detected",
        "path_traversal",
        "auth_bypass",
        "scraping",
        "shared_device",
        "shared_ip",
        "stage_progression",
    }

    # ─── Redis Keys ───────────────────────────────────────
    AUDIT_KEY = "am:audit"
    ACTION_KEY_PREFIX = "am:action:"
    COOLDOWN_KEY_PREFIX = "am:cooldown:"

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
                logger.error("auto_mitigation_redis_init_failed", error=str(e))
                return None
        return cls._redis_client

    @staticmethod
    def _action_key(entity_type: str, entity_value: str) -> str:
        return f"{AutoMitigation.ACTION_KEY_PREFIX}{entity_type}:{entity_value}"

    @staticmethod
    def _cooldown_key(entity_type: str, entity_value: str) -> str:
        return f"{AutoMitigation.COOLDOWN_KEY_PREFIX}{entity_type}:{entity_value}"

    @classmethod
    def _risk_to_action(cls, risk_score: int) -> MitigationAction:
        """بيحوّل risk score لـ action."""
        for action, (low, high) in cls.THRESHOLDS.items():
            if low <= risk_score <= high:
                return action
        return MitigationAction.ALLOW

    # ═══════════════════════════════════════════════════════
    #  Whitelist Check (Defensive — supports multiple signatures)
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def _check_whitelist(
        cls,
        entity_type: str,
        entity_value: str,
    ) -> bool:
        """
        بيتحقق لو الكيان في الـ whitelist.

        Defensive: يدعم عدة method signatures للتوافق مع
        إصدارات مختلفة من WhitelistManager.
        """
        try:
            from app.core.whitelist_manager import WhitelistManager

            # ─── محاولة 1: check() method ───
            if hasattr(WhitelistManager, "check"):
                try:
                    result = await WhitelistManager.check(
                        entity_type=entity_type,
                        entity_value=entity_value,
                    )
                    if isinstance(result, dict):
                        return bool(result.get("is_whitelisted", False))
                    return bool(result)
                except (TypeError, AttributeError):
                    pass

            # ─── محاولة 2: is_whitelisted() بـ signatures مختلفة ───
            if hasattr(WhitelistManager, "is_whitelisted"):
                signatures = [
                    {"identifier": entity_value, "type": entity_type},
                    {"identifier": entity_value},
                    {"value": entity_value, "type": entity_type},
                    {"value": entity_value},
                    {"user_id": entity_value},
                    {"ip": entity_value},
                    {"item": entity_value},
                    {"key": entity_value},
                ]
                for kwargs in signatures:
                    try:
                        result = await WhitelistManager.is_whitelisted(**kwargs)
                        if isinstance(result, dict):
                            return bool(result.get("is_whitelisted", False))
                        return bool(result)
                    except TypeError:
                        continue

            # ─── محاولة 3: methods منفصلة حسب النوع ───
            if entity_type == "ip":
                for method_name in ["is_ip_whitelisted", "check_ip"]:
                    if hasattr(WhitelistManager, method_name):
                        method = getattr(WhitelistManager, method_name)
                        try:
                            return bool(await method(entity_value))
                        except TypeError:
                            continue

            if entity_type == "user":
                for method_name in ["is_user_whitelisted", "check_user"]:
                    if hasattr(WhitelistManager, method_name):
                        method = getattr(WhitelistManager, method_name)
                        try:
                            return bool(await method(entity_value))
                        except TypeError:
                            continue

            logger.debug(
                "whitelist_no_matching_method",
                entity_type=entity_type,
            )
            return False

        except Exception as e:
            logger.debug("whitelist_check_failed", error=str(e))
            return False

    # ═══════════════════════════════════════════════════════
    #  Threat Intel Check
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def _check_threat_intel(
        cls,
        ip: str,
    ) -> Dict[str, Any]:
        """بيفحص الـ IP ضد threat intel."""
        try:
            from app.core.threat_intel import ThreatIntel

            result = await ThreatIntel.check_ip(ip)
            if result.get("success"):
                return {
                    "is_threat": result.get("is_threat", False),
                    "threat_score": result.get("threat_score", 0),
                    "flags": result.get("flags", []),
                }
        except Exception as e:
            logger.debug("threat_intel_check_failed", error=str(e))

        return {"is_threat": False, "threat_score": 0, "flags": []}

    # ═══════════════════════════════════════════════════════
    #  Escalation Logic
    # ═══════════════════════════════════════════════════════

    @classmethod
    def _escalate_action(
        cls,
        base_action: MitigationAction,
        signals: List[str],
        threat_intel: Dict[str, Any],
    ) -> MitigationAction:
        """بيرفع مستوى الـ action لو فيه signals حرجة."""
        critical_count = sum(
            1 for s in signals if s.lower() in cls.CRITICAL_SIGNALS
        )
        high_count = sum(
            1 for s in signals if s.lower() in cls.HIGH_SIGNALS
        )

        escalation_level = 0

        if critical_count >= 2:
            escalation_level = 3
        elif critical_count == 1:
            escalation_level = 2
        elif high_count >= 3:
            escalation_level = 1

        if threat_intel.get("is_threat"):
            escalation_level += 1

        action_levels = {
            MitigationAction.ALLOW: 0,
            MitigationAction.MONITOR: 1,
            MitigationAction.CHALLENGE: 2,
            MitigationAction.RATE_LIMIT: 3,
            MitigationAction.TEMP_BLOCK: 4,
            MitigationAction.BLOCK: 5,
        }

        base_level = action_levels.get(base_action, 0)
        new_level = min(base_level + escalation_level, 5)

        for action, level in action_levels.items():
            if level == new_level:
                return action

        return base_action

    # ═══════════════════════════════════════════════════════
    #  Main Evaluation
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def evaluate(
        cls,
        entity_type: str,
        entity_value: str,
        *,
        risk_score: int = 0,
        signals: Optional[List[str]] = None,
        context: Optional[Dict[str, Any]] = None,
        apply_action: bool = True,
    ) -> Dict[str, Any]:
        """
        بيقيّم الكيان وياخد قرار mitigation.

        Args:
            entity_type: نوع الكيان (ip/user/session)
            entity_value: قيمة الكيان
            risk_score: 0-100 من detectors
            signals: قائمة signals
            context: معلومات إضافية
            apply_action: يطبق الـ action فوراً؟

        Returns:
            dict فيه القرار والتفاصيل
        """
        if not entity_type or not entity_value:
            return {"success": False, "error": "missing_entity_info"}

        try:
            signals = signals or []
            context = context or {}

            reasons: List[str] = []

            # ─── 1. Whitelist check (أولوية قصوى) ───
            is_whitelisted = await cls._check_whitelist(
                entity_type, entity_value
            )

            if is_whitelisted:
                return {
                    "success": True,
                    "entity": f"{entity_type}:{entity_value}",
                    "action": MitigationAction.ALLOW.value,
                    "risk_score": risk_score,
                    "level": "whitelisted",
                    "reasons": ["whitelisted"],
                    "applied": False,
                    "duration_seconds": 0,
                }

            # ─── 2. Threat Intel (للـ IPs بس) ───
            threat_intel = {"is_threat": False, "threat_score": 0, "flags": []}
            if entity_type == "ip":
                threat_intel = await cls._check_threat_intel(entity_value)

                if threat_intel["is_threat"]:
                    risk_score = min(
                        risk_score + threat_intel["threat_score"] // 2,
                        100,
                    )
                    reasons.append(
                        f"threat_intel: {threat_intel['flags']}"
                    )

            # ─── 3. Base action من risk_score ───
            base_action = cls._risk_to_action(risk_score)

            # ─── 4. Escalation ───
            final_action = cls._escalate_action(
                base_action, signals, threat_intel
            )

            if final_action != base_action:
                reasons.append(
                    f"escalated from {base_action.value} to {final_action.value}"
                )

            # ─── 5. حدد المدة ───
            duration = 0
            if final_action == MitigationAction.RATE_LIMIT:
                duration = cls.RATE_LIMIT_DURATION
            elif final_action == MitigationAction.TEMP_BLOCK:
                duration = cls.TEMP_BLOCK_DURATION
            elif final_action == MitigationAction.BLOCK:
                duration = cls.PERMANENT_BLOCK_FLAG

            # ─── 6. Level ───
            level = "clean"
            if risk_score >= 85:
                level = "critical"
            elif risk_score >= 70:
                level = "high"
            elif risk_score >= 50:
                level = "medium"
            elif risk_score >= 30:
                level = "low"

            # ─── 7. Cooldown check ───
            client = cls.get_client()
            cooldown_active = False

            if client and apply_action:
                cooldown_key = cls._cooldown_key(entity_type, entity_value)
                if await client.exists(cooldown_key):
                    cooldown_active = True
                    reasons.append("cooldown_active")

            # ─── 8. Apply action ───
            applied = False

            if apply_action and not cooldown_active and client:
                action_key = cls._action_key(entity_type, entity_value)
                await client.set(
                    action_key,
                    json.dumps({
                        "action": final_action.value,
                        "risk_score": risk_score,
                        "signals": signals,
                        "reasons": reasons,
                        "applied_at": time.time(),
                        "duration": duration,
                    }),
                    ex=max(duration, cls.ACTION_TTL) if duration > 0 else cls.ACTION_TTL,
                )

                cooldown_key = cls._cooldown_key(entity_type, entity_value)
                await client.set(
                    cooldown_key,
                    "1",
                    ex=cls.COOLDOWN_SECONDS,
                )

                await cls._log_action(
                    entity_type=entity_type,
                    entity_value=entity_value,
                    action=final_action.value,
                    risk_score=risk_score,
                    signals=signals,
                    reasons=reasons,
                    duration=duration,
                )

                applied = True

            # ─── 9. Log ───
            if final_action in (
                MitigationAction.TEMP_BLOCK,
                MitigationAction.BLOCK,
            ):
                logger.warning(
                    "auto_mitigation_action",
                    entity=f"{entity_type}:{entity_value}",
                    action=final_action.value,
                    risk_score=risk_score,
                    duration=duration,
                )
            elif final_action != MitigationAction.ALLOW:
                logger.info(
                    "auto_mitigation_action",
                    entity=f"{entity_type}:{entity_value}",
                    action=final_action.value,
                    risk_score=risk_score,
                )

            return {
                "success": True,
                "entity": f"{entity_type}:{entity_value}",
                "action": final_action.value,
                "base_action": base_action.value,
                "risk_score": risk_score,
                "level": level,
                "reasons": reasons,
                "signals": signals,
                "signal_count": len(signals),
                "duration_seconds": duration,
                "applied": applied,
                "cooldown_active": cooldown_active,
                "threat_intel": threat_intel if entity_type == "ip" else None,
                "evaluated_at": time.time(),
            }

        except Exception as e:
            logger.error("auto_mitigation_evaluate_failed", error=str(e))
            return {"success": False, "error": str(e)}

    # ═══════════════════════════════════════════════════════
    #  Audit Trail
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def _log_action(
        cls,
        entity_type: str,
        entity_value: str,
        action: str,
        risk_score: int,
        signals: List[str],
        reasons: List[str],
        duration: int,
    ) -> None:
        """بيسجل الـ action في audit trail."""
        client = cls.get_client()
        if not client:
            return

        try:
            entry = {
                "timestamp": time.time(),
                "entity_type": entity_type,
                "entity_value": entity_value,
                "action": action,
                "risk_score": risk_score,
                "signals": signals,
                "reasons": reasons,
                "duration": duration,
            }

            await client.lpush(cls.AUDIT_KEY, json.dumps(entry))
            await client.ltrim(cls.AUDIT_KEY, 0, 9999)
            await client.expire(cls.AUDIT_KEY, cls.ACTION_TTL)

        except Exception as e:
            logger.error("auto_mitigation_log_failed", error=str(e))

    @classmethod
    async def get_audit_log(
        cls,
        limit: int = 100,
        entity_type: Optional[str] = None,
        entity_value: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """بيرجع audit log."""
        client = cls.get_client()
        if not client:
            return []

        try:
            raw_list = await client.lrange(cls.AUDIT_KEY, 0, limit * 3)

            results = []
            for raw in raw_list:
                try:
                    entry = json.loads(raw)
                except json.JSONDecodeError:
                    continue

                if entity_type and entry.get("entity_type") != entity_type:
                    continue
                if entity_value and entry.get("entity_value") != entity_value:
                    continue

                results.append(entry)

                if len(results) >= limit:
                    break

            return results

        except Exception as e:
            logger.error("auto_mitigation_audit_failed", error=str(e))
            return []

    # ═══════════════════════════════════════════════════════
    #  Action Status
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def get_action(
        cls,
        entity_type: str,
        entity_value: str,
    ) -> Optional[Dict[str, Any]]:
        """بيرجع الـ action الحالي للكيان."""
        client = cls.get_client()
        if not client:
            return None

        try:
            action_key = cls._action_key(entity_type, entity_value)
            raw = await client.get(action_key)

            if not raw:
                return None

            data = json.loads(raw)

            applied_at = data.get("applied_at", 0)
            duration = data.get("duration", 0)

            if duration > 0:
                expires_at = applied_at + duration
                if time.time() > expires_at:
                    await client.delete(action_key)
                    return None

            return data

        except Exception as e:
            logger.error("auto_mitigation_get_action_failed", error=str(e))
            return None

    @classmethod
    async def is_blocked(
        cls,
        entity_type: str,
        entity_value: str,
    ) -> Dict[str, Any]:
        """بيتحقق لو الكيان محظور."""
        action = await cls.get_action(entity_type, entity_value)

        if not action:
            return {"blocked": False, "action": None}

        act = action.get("action")

        if act in (
            MitigationAction.TEMP_BLOCK.value,
            MitigationAction.BLOCK.value,
        ):
            return {
                "blocked": True,
                "action": act,
                "details": action,
            }

        return {"blocked": False, "action": act}

    @classmethod
    async def is_rate_limited(
        cls,
        entity_type: str,
        entity_value: str,
    ) -> Dict[str, Any]:
        """بيتحقق لو الكيان rate-limited."""
        action = await cls.get_action(entity_type, entity_value)

        if not action:
            return {"rate_limited": False}

        if action.get("action") == MitigationAction.RATE_LIMIT.value:
            return {
                "rate_limited": True,
                "details": action,
            }

        return {"rate_limited": False}

    @classmethod
    async def needs_challenge(
        cls,
        entity_type: str,
        entity_value: str,
    ) -> bool:
        """بيتحقق لو الكيان محتاج challenge."""
        action = await cls.get_action(entity_type, entity_value)
        if not action:
            return False
        return action.get("action") == MitigationAction.CHALLENGE.value

    # ═══════════════════════════════════════════════════════
    #  Manual Override
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def manual_block(
        cls,
        entity_type: str,
        entity_value: str,
        *,
        reason: str = "manual",
        duration: int = 0,
    ) -> Dict[str, Any]:
        """بيحظر يدوياً."""
        client = cls.get_client()
        if not client:
            return {"success": False, "error": "redis_unavailable"}

        try:
            action_key = cls._action_key(entity_type, entity_value)

            data = {
                "action": MitigationAction.BLOCK.value,
                "risk_score": 100,
                "signals": [],
                "reasons": [reason, "manual_block"],
                "applied_at": time.time(),
                "duration": duration,
                "manual": True,
            }

            ttl = duration if duration > 0 else cls.ACTION_TTL
            await client.set(action_key, json.dumps(data), ex=ttl)

            await cls._log_action(
                entity_type=entity_type,
                entity_value=entity_value,
                action=MitigationAction.BLOCK.value,
                risk_score=100,
                signals=[],
                reasons=[reason, "manual_block"],
                duration=duration,
            )

            logger.warning(
                "auto_mitigation_manual_block",
                entity=f"{entity_type}:{entity_value}",
                reason=reason,
            )

            return {"success": True, "action": "block"}

        except Exception as e:
            logger.error("auto_mitigation_manual_block_failed", error=str(e))
            return {"success": False, "error": str(e)}

    @classmethod
    async def unblock(
        cls,
        entity_type: str,
        entity_value: str,
    ) -> Dict[str, Any]:
        """بيرفع الحظر."""
        client = cls.get_client()
        if not client:
            return {"success": False, "error": "redis_unavailable"}

        try:
            action_key = cls._action_key(entity_type, entity_value)
            cooldown_key = cls._cooldown_key(entity_type, entity_value)

            await client.delete(action_key, cooldown_key)

            await cls._log_action(
                entity_type=entity_type,
                entity_value=entity_value,
                action="unblock",
                risk_score=0,
                signals=[],
                reasons=["manual_unblock"],
                duration=0,
            )

            logger.info(
                "auto_mitigation_unblock",
                entity=f"{entity_type}:{entity_value}",
            )

            return {"success": True}

        except Exception as e:
            logger.error("auto_mitigation_unblock_failed", error=str(e))
            return {"success": False, "error": str(e)}

    # ═══════════════════════════════════════════════════════
    #  Stats
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def get_stats(cls) -> Dict[str, Any]:
        """بيرجع إحصائيات الـ auto mitigation."""
        client = cls.get_client()
        if not client:
            return {"success": False, "error": "redis_unavailable"}

        try:
            actions_count = 0
            cursor = 0
            action_counts: Dict[str, int] = {}

            while True:
                cursor, keys = await client.scan(
                    cursor=cursor,
                    match=f"{cls.ACTION_KEY_PREFIX}*",
                    count=100,
                )
                for key in keys:
                    actions_count += 1
                    raw = await client.get(key)
                    if raw:
                        try:
                            data = json.loads(raw)
                            action = data.get("action", "unknown")
                            action_counts[action] = action_counts.get(action, 0) + 1
                        except json.JSONDecodeError:
                            continue

                if cursor == 0:
                    break

            audit_count = await client.llen(cls.AUDIT_KEY)

            return {
                "success": True,
                "active_actions": actions_count,
                "actions_breakdown": action_counts,
                "audit_entries": audit_count,
            }

        except Exception as e:
            logger.error("auto_mitigation_stats_failed", error=str(e))
            return {"success": False, "error": str(e)}

    # ═══════════════════════════════════════════════════════
    #  Utilities
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def clear_entity(
        cls,
        entity_type: str,
        entity_value: str,
    ) -> Dict[str, Any]:
        """بيمسح بيانات كيان."""
        client = cls.get_client()
        if not client:
            return {"success": False, "error": "redis_unavailable"}

        try:
            keys = [
                cls._action_key(entity_type, entity_value),
                cls._cooldown_key(entity_type, entity_value),
            ]
            await client.delete(*keys)

            return {"success": True}

        except Exception as e:
            logger.error("auto_mitigation_clear_failed", error=str(e))
            return {"success": False, "error": str(e)}

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
                    match="am:*",
                    count=100,
                )
                if keys:
                    await client.delete(*keys)
                if cursor == 0:
                    break

            logger.info("auto_mitigation_all_cleared")
        except Exception as e:
            logger.error("auto_mitigation_clear_all_failed", error=str(e))

    @classmethod
    async def close(cls) -> None:
        """بتقفل Redis."""
        if cls._redis_client:
            await cls._redis_client.close()
            cls._redis_client = None


# ─── Standalone functions ─────────────────────────────

async def evaluate(
    entity_type: str,
    entity_value: str,
    **kwargs,
) -> Dict[str, Any]:
    """Shortcut for AutoMitigation.evaluate."""
    return await AutoMitigation.evaluate(entity_type, entity_value, **kwargs)


async def is_blocked(
    entity_type: str,
    entity_value: str,
) -> Dict[str, Any]:
    """Shortcut for AutoMitigation.is_blocked."""
    return await AutoMitigation.is_blocked(entity_type, entity_value)


async def manual_block(
    entity_type: str,
    entity_value: str,
    **kwargs,
) -> Dict[str, Any]:
    """Shortcut for AutoMitigation.manual_block."""
    return await AutoMitigation.manual_block(
        entity_type, entity_value, **kwargs
    )


async def unblock(
    entity_type: str,
    entity_value: str,
) -> Dict[str, Any]:
    """Shortcut for AutoMitigation.unblock."""
    return await AutoMitigation.unblock(entity_type, entity_value)