"""
Feedback Loop — Continuous learning from decisions & outcomes.

بيوفر:
- Feedback recording (true_positive, false_positive, etc.)
- Auto-learning from admin decisions
- Threshold adjustment recommendations
- Confidence scoring updates
- Feedback statistics & trends
- Redis-backed
- Per-detector feedback tracking
- Learning rate control

الفكرة:
- كل decision بيتسجل مع نتيجة (feedback)
- النظام بيتعلم من الـ feedback
- بيعدّل الـ thresholds تدريجياً
- بيحسّن الـ confidence scores

أنواع الـ feedback:
- TRUE_POSITIVE: القرار كان صح (تهديد فعلي)
- FALSE_POSITIVE: القرار كان غلط (نظام حظر بريء)
- TRUE_NEGATIVE: القرار كان صح (مفيش تهديد)
- FALSE_NEGATIVE: القرار كان غلط (فات تهديد)

الاستخدام:
- auto_mitigation.py
- defense_service.py
- admin endpoints
- ML retraining pipeline
"""

import json
import math
import time
from collections import defaultdict
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import redis.asyncio as redis
import structlog

from app.core.config import settings

logger = structlog.get_logger()


class FeedbackType(str, Enum):
    """أنواع الـ feedback."""
    TRUE_POSITIVE = "true_positive"      # القرار صح، كان في تهديد
    FALSE_POSITIVE = "false_positive"    # القرار غلط، مفيش تهديد
    TRUE_NEGATIVE = "true_negative"      # القرار صح، مفيش تهديد
    FALSE_NEGATIVE = "false_negative"    # القرار غلط، كان في تهديد
    UNCERTAIN = "uncertain"              # مش متأكد


class FeedbackSource(str, Enum):
    """مصادر الـ feedback."""
    ADMIN = "admin"              # من admin
    AUTO = "auto"                # automatic (من النظام)
    USER = "user"                # من المستخدم
    EXTERNAL = "external"        # من مصدر خارجي


class FeedbackLoop:
    """
    Feedback Loop System.

    الفكرة:
    - نسجل feedback مع كل decision
    - نحلل الأنماط
    - نولّد recommendations للتحسين
    """

    _redis_client: Optional[redis.Redis] = None

    # ─── Config ────────────────────────────────────────────
    FEEDBACK_TTL = 86400 * 90    # 90 يوم
    MAX_FEEDBACK_PER_ENTITY = 50
    MAX_RECENT_FEEDBACK = 10000

    # ─── Learning Rate ────────────────────────────────────
    # كم نعدّل الـ threshold بناءً على feedback
    LEARNING_RATE = 0.05         # 5% adjustment
    MIN_SAMPLES_FOR_ADJUSTMENT = 20

    # ─── Threshold Bounds ─────────────────────────────────
    MIN_THRESHOLD = 20
    MAX_THRESHOLD = 95

    # ─── Redis Keys ───────────────────────────────────────
    FEEDBACK_KEY_PREFIX = "fb:entity:"
    GLOBAL_KEY = "fb:global"
    RECENT_KEY = "fb:recent"
    STATS_KEY = "fb:stats"
    ADJUSTMENTS_KEY = "fb:adjustments"

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
                logger.error("feedback_loop_redis_init_failed", error=str(e))
                return None
        return cls._redis_client

    @staticmethod
    def _entity_key(entity_type: str, entity_value: str) -> str:
        return f"{FeedbackLoop.FEEDBACK_KEY_PREFIX}{entity_type}:{entity_value}"

    @staticmethod
    def _is_positive_feedback(feedback_type: str) -> bool:
        """بيتحقق لو الـ feedback إيجابي (القرار كان صح)."""
        return feedback_type in (
            FeedbackType.TRUE_POSITIVE.value,
            FeedbackType.TRUE_NEGATIVE.value,
        )

    @staticmethod
    def _is_false_decision(feedback_type: str) -> bool:
        """بيتحقق لو الـ decision كان غلط."""
        return feedback_type in (
            FeedbackType.FALSE_POSITIVE.value,
            FeedbackType.FALSE_NEGATIVE.value,
        )

    # ═══════════════════════════════════════════════════════
    #  Recording Feedback
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def record_feedback(
        cls,
        entity_type: str,
        entity_value: str,
        *,
        feedback_type: str,
        original_action: Optional[str] = None,
        risk_score: Optional[int] = None,
        signals: Optional[List[str]] = None,
        source: str = FeedbackSource.ADMIN.value,
        feedback_by: Optional[str] = None,
        notes: Optional[str] = None,
        detector: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        بيسجل feedback على decision سابق.

        Args:
            entity_type: نوع الكيان
            entity_value: قيمة الكيان
            feedback_type: true_positive/false_positive/true_negative/false_negative
            original_action: القرار اللي اتاخد
            risk_score: الـ risk score الأصلي
            signals: الـ signals اللي اتكشفت
            source: مصدر الـ feedback
            feedback_by: مين عمل الـ feedback
            notes: ملاحظات
            detector: اسم الـ detector

        Returns:
            dict فيه success + stats
        """
        client = cls.get_client()
        if not client:
            return {"success": False, "error": "redis_unavailable"}

        try:
            if not entity_type or not entity_value:
                return {"success": False, "error": "missing_entity_info"}

            # تحقق من نوع الـ feedback
            try:
                ft = FeedbackType(feedback_type)
            except ValueError:
                return {
                    "success": False,
                    "error": "invalid_feedback_type",
                    "valid_types": [t.value for t in FeedbackType],
                }

            now = time.time()

            entry = {
                "timestamp": now,
                "entity_type": entity_type,
                "entity_value": entity_value,
                "feedback_type": ft.value,
                "original_action": original_action,
                "risk_score": risk_score,
                "signals": signals or [],
                "source": source,
                "feedback_by": feedback_by,
                "notes": notes,
                "detector": detector,
            }

            # 1. خزّن في entity history
            entity_key = cls._entity_key(entity_type, entity_value)
            await client.lpush(entity_key, json.dumps(entry))
            await client.ltrim(entity_key, 0, cls.MAX_FEEDBACK_PER_ENTITY - 1)
            await client.expire(entity_key, cls.FEEDBACK_TTL)

            # 2. خزّن في recent
            await client.lpush(cls.RECENT_KEY, json.dumps(entry))
            await client.ltrim(cls.RECENT_KEY, 0, cls.MAX_RECENT_FEEDBACK - 1)
            await client.expire(cls.RECENT_KEY, cls.FEEDBACK_TTL)

            # 3. حدّث الإحصائيات
            await cls._update_stats(entry)

            # 4. حدّث الـ detector-specific stats
            if detector:
                await cls._update_detector_stats(detector, ft.value)

            # 5. سجل
            is_positive = cls._is_positive_feedback(ft.value)
            log_fn = logger.info if is_positive else logger.warning

            log_fn(
                "feedback_recorded",
                entity=f"{entity_type}:{entity_value}",
                feedback_type=ft.value,
                source=source,
                detector=detector,
            )

            # 6. احسب الإحصائيات الحالية
            stats = await cls.get_stats()

            return {
                "success": True,
                "entity": f"{entity_type}:{entity_value}",
                "feedback_type": ft.value,
                "is_positive": is_positive,
                "recorded_at": now,
                "stats": stats,
            }

        except Exception as e:
            logger.error("feedback_record_failed", error=str(e))
            return {"success": False, "error": str(e)}

    @classmethod
    async def _update_stats(cls, entry: Dict[str, Any]) -> None:
        """بيحدّث الإحصائيات العامة."""
        client = cls.get_client()
        if not client:
            return

        try:
            stats_key = cls.STATS_KEY
            feedback_type = entry["feedback_type"]

            # total counts
            await client.hincrby(stats_key, "total", 1)
            await client.hincrby(stats_key, feedback_type, 1)

            # sources
            source = entry.get("source", "unknown")
            await client.hincrby(stats_key, f"source:{source}", 1)

            # signals
            for signal in entry.get("signals", []):
                await client.hincrby(stats_key, f"signal:{signal}", 1)

            # آخر تحديث
            await client.hset(stats_key, "last_updated", str(time.time()))
            await client.expire(stats_key, cls.FEEDBACK_TTL)

        except Exception as e:
            logger.debug("feedback_stats_update_failed", error=str(e))

    @classmethod
    async def _update_detector_stats(
        cls,
        detector: str,
        feedback_type: str,
    ) -> None:
        """بيحدّث إحصائيات الـ detector."""
        client = cls.get_client()
        if not client:
            return

        try:
            key = f"{cls.STATS_KEY}:detector:{detector}"
            await client.hincrby(key, "total", 1)
            await client.hincrby(key, feedback_type, 1)
            await client.hset(key, "last_updated", str(time.time()))
            await client.expire(key, cls.FEEDBACK_TTL)

        except Exception as e:
            logger.debug("feedback_detector_stats_failed", error=str(e))

    # ═══════════════════════════════════════════════════════
    #  Analysis
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def get_stats(cls) -> Dict[str, Any]:
        """بيرجع الإحصائيات العامة."""
        client = cls.get_client()
        if not client:
            return {"success": False, "error": "redis_unavailable"}

        try:
            raw = await client.hgetall(cls.STATS_KEY)

            if not raw:
                return {
                    "success": True,
                    "total": 0,
                    "accuracy": 0.0,
                    "false_positive_rate": 0.0,
                    "false_negative_rate": 0.0,
                }

            total = int(raw.get("total", 0))
            tp = int(raw.get("true_positive", 0))
            fp = int(raw.get("false_positive", 0))
            tn = int(raw.get("true_negative", 0))
            fn = int(raw.get("false_negative", 0))

            # احسب النسب
            accuracy = (tp + tn) / total if total > 0 else 0.0
            fp_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            fn_rate = fn / (fn + tp) if (fn + tp) > 0 else 0.0
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

            # f1 score
            f1 = (
                2 * (precision * recall) / (precision + recall)
                if (precision + recall) > 0 else 0.0
            )

            return {
                "success": True,
                "total": total,
                "true_positive": tp,
                "false_positive": fp,
                "true_negative": tn,
                "false_negative": fn,
                "accuracy": round(accuracy, 4),
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1_score": round(f1, 4),
                "false_positive_rate": round(fp_rate, 4),
                "false_negative_rate": round(fn_rate, 4),
            }

        except Exception as e:
            logger.error("feedback_get_stats_failed", error=str(e))
            return {"success": False, "error": str(e)}

    @classmethod
    async def get_detector_stats(cls) -> Dict[str, Any]:
        """بيرجع إحصائيات كل detector على حدة."""
        client = cls.get_client()
        if not client:
            return {"success": False, "error": "redis_unavailable"}

        try:
            detectors: Dict[str, Dict[str, Any]] = {}

            cursor = 0
            while True:
                cursor, keys = await client.scan(
                    cursor=cursor,
                    match=f"{cls.STATS_KEY}:detector:*",
                    count=100,
                )
                for key in keys:
                    detector_name = key.split(":")[-1]
                    raw = await client.hgetall(key)

                    if not raw:
                        continue

                    total = int(raw.get("total", 0))
                    tp = int(raw.get("true_positive", 0))
                    fp = int(raw.get("false_positive", 0))
                    tn = int(raw.get("true_negative", 0))
                    fn = int(raw.get("false_negative", 0))

                    accuracy = (tp + tn) / total if total > 0 else 0.0
                    fp_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0
                    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0

                    detectors[detector_name] = {
                        "total": total,
                        "true_positive": tp,
                        "false_positive": fp,
                        "true_negative": tn,
                        "false_negative": fn,
                        "accuracy": round(accuracy, 4),
                        "precision": round(precision, 4),
                        "false_positive_rate": round(fp_rate, 4),
                    }

                if cursor == 0:
                    break

            return {
                "success": True,
                "detectors": detectors,
                "total_detectors": len(detectors),
            }

        except Exception as e:
            logger.error("feedback_detector_stats_failed", error=str(e))
            return {"success": False, "error": str(e)}

    # ═══════════════════════════════════════════════════════
    #  Auto-Learning: Threshold Adjustments
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def get_threshold_adjustments(
        cls,
        detector: Optional[str] = None,
        current_threshold: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        بيرجع توصيات لتعديل الـ threshold بناءً على الـ feedback.

        المنطق:
        - FP rate عالي → ارفع الـ threshold (كن أقل حساسية)
        - FN rate عالي → اخفض الـ threshold (كن أكثر حساسية)

        Args:
            detector: اسم الـ detector (اختياري)
            current_threshold: الـ threshold الحالي

        Returns:
            dict فيه:
            - recommended_threshold
            - adjustment
            - reason
            - confidence
        """
        try:
            if detector:
                stats = await cls._get_detector_stats(detector)
            else:
                stats = await cls.get_stats()

            if not stats.get("success"):
                return {"success": False, "error": "stats_unavailable"}

            total = stats.get("total", 0)

            # محتاجين عينة كافية
            if total < cls.MIN_SAMPLES_FOR_ADJUSTMENT:
                return {
                    "success": True,
                    "adjustment": 0,
                    "recommended_threshold": current_threshold,
                    "reason": "insufficient_samples",
                    "samples": total,
                    "min_required": cls.MIN_SAMPLES_FOR_ADJUSTMENT,
                }

            # احسب rates
            fp_rate = stats.get("false_positive_rate", 0.0)
            fn_rate = stats.get("false_negative_rate", 0.0)

            # القاعدة:
            # FP > 10% → ارفع الـ threshold
            # FN > 10% → اخفض الـ threshold
            adjustment = 0
            reason = "balanced"

            if fp_rate > 0.10 and fp_rate > fn_rate:
                # FP عالي → ارفع الـ threshold
                magnitude = min(fp_rate * 100, 20)  # max 20 points
                adjustment = int(magnitude * cls.LEARNING_RATE * 20)
                reason = f"high_false_positive_rate ({fp_rate:.2%})"

            elif fn_rate > 0.10 and fn_rate > fp_rate:
                # FN عالي → اخفض الـ threshold
                magnitude = min(fn_rate * 100, 20)
                adjustment = -int(magnitude * cls.LEARNING_RATE * 20)
                reason = f"high_false_negative_rate ({fn_rate:.2%})"

            # احسب الـ threshold الجديد
            recommended = None
            if current_threshold is not None:
                recommended = current_threshold + adjustment

                # حدود
                recommended = max(
                    cls.MIN_THRESHOLD,
                    min(cls.MAX_THRESHOLD, recommended),
                )

            # ثقة التوصية
            confidence = min(total / 100, 1.0)

            # سجل التوصية
            if adjustment != 0:
                await cls._log_adjustment(
                    detector=detector or "global",
                    old_threshold=current_threshold,
                    new_threshold=recommended,
                    adjustment=adjustment,
                    reason=reason,
                    confidence=confidence,
                )

            return {
                "success": True,
                "detector": detector or "global",
                "adjustment": adjustment,
                "current_threshold": current_threshold,
                "recommended_threshold": recommended,
                "reason": reason,
                "confidence": round(confidence, 3),
                "fp_rate": round(fp_rate, 4),
                "fn_rate": round(fn_rate, 4),
                "samples": total,
            }

        except Exception as e:
            logger.error("feedback_adjustment_failed", error=str(e))
            return {"success": False, "error": str(e)}

    @classmethod
    async def _get_detector_stats(cls, detector: str) -> Dict[str, Any]:
        """بيرجع stats detector معين."""
        client = cls.get_client()
        if not client:
            return {"success": False, "error": "redis_unavailable"}

        try:
            key = f"{cls.STATS_KEY}:detector:{detector}"
            raw = await client.hgetall(key)

            if not raw:
                return {"success": True, "total": 0}

            total = int(raw.get("total", 0))
            tp = int(raw.get("true_positive", 0))
            fp = int(raw.get("false_positive", 0))
            tn = int(raw.get("true_negative", 0))
            fn = int(raw.get("false_negative", 0))

            return {
                "success": True,
                "total": total,
                "true_positive": tp,
                "false_positive": fp,
                "true_negative": tn,
                "false_negative": fn,
                "false_positive_rate": fp / (fp + tn) if (fp + tn) > 0 else 0.0,
                "false_negative_rate": fn / (fn + tp) if (fn + tp) > 0 else 0.0,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    @classmethod
    async def _log_adjustment(
        cls,
        detector: str,
        old_threshold: Optional[int],
        new_threshold: Optional[int],
        adjustment: int,
        reason: str,
        confidence: float,
    ) -> None:
        """بيسجل التوصية في history."""
        client = cls.get_client()
        if not client:
            return

        try:
            entry = {
                "timestamp": time.time(),
                "detector": detector,
                "old_threshold": old_threshold,
                "new_threshold": new_threshold,
                "adjustment": adjustment,
                "reason": reason,
                "confidence": confidence,
            }

            await client.lpush(cls.ADJUSTMENTS_KEY, json.dumps(entry))
            await client.ltrim(cls.ADJUSTMENTS_KEY, 0, 999)
            await client.expire(cls.ADJUSTMENTS_KEY, cls.FEEDBACK_TTL)

        except Exception as e:
            logger.debug("feedback_log_adjustment_failed", error=str(e))

    # ═══════════════════════════════════════════════════════
    #  Entity Feedback History
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def get_entity_feedback(
        cls,
        entity_type: str,
        entity_value: str,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """بيرجع feedback كيان معين."""
        client = cls.get_client()
        if not client:
            return []

        try:
            entity_key = cls._entity_key(entity_type, entity_value)
            raw_list = await client.lrange(entity_key, 0, limit - 1)

            feedback = []
            for raw in raw_list:
                try:
                    feedback.append(json.loads(raw))
                except json.JSONDecodeError:
                    continue

            return feedback

        except Exception as e:
            logger.error("feedback_entity_history_failed", error=str(e))
            return []

    @classmethod
    async def get_recent_feedback(
        cls,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """بيرجع آخر الـ feedback."""
        client = cls.get_client()
        if not client:
            return []

        try:
            raw_list = await client.lrange(cls.RECENT_KEY, 0, limit - 1)

            feedback = []
            for raw in raw_list:
                try:
                    feedback.append(json.loads(raw))
                except json.JSONDecodeError:
                    continue

            return feedback

        except Exception as e:
            logger.error("feedback_recent_failed", error=str(e))
            return []

    @classmethod
    async def get_adjustment_history(
        cls,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """بيرجع تاريخ التعديلات."""
        client = cls.get_client()
        if not client:
            return []

        try:
            raw_list = await client.lrange(cls.ADJUSTMENTS_KEY, 0, limit - 1)

            history = []
            for raw in raw_list:
                try:
                    history.append(json.loads(raw))
                except json.JSONDecodeError:
                    continue

            return history

        except Exception as e:
            logger.error("feedback_adjustments_failed", error=str(e))
            return []

    # ═══════════════════════════════════════════════════════
    #  Auto-Feedback from Actions
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def auto_record_from_action(
        cls,
        entity_type: str,
        entity_value: str,
        action: str,
        risk_score: int,
        signals: List[str],
        was_blocked: bool,
    ) -> Dict[str, Any]:
        """
        بيسجل feedback تلقائي من action.

        المنطق:
        - لو action = block و signals عالية → true_positive
        - لو action = block و signals منخفضة → uncertain
        - لو action = allow و signals عالية → false_negative
        - لو action = allow و signals منخفضة → true_negative
        """
        try:
            # حدد الـ feedback type
            high_risk = risk_score >= 70
            has_critical = any(
                s.lower() in (
                    "sql_injection", "rce_attempt", "beacon_pattern",
                    "c2_traffic", "data_exfiltration",
                )
                for s in signals
            )

            if was_blocked:
                if high_risk or has_critical:
                    feedback_type = FeedbackType.TRUE_POSITIVE.value
                else:
                    feedback_type = FeedbackType.UNCERTAIN.value
            else:
                if high_risk or has_critical:
                    feedback_type = FeedbackType.FALSE_NEGATIVE.value
                else:
                    feedback_type = FeedbackType.TRUE_NEGATIVE.value

            return await cls.record_feedback(
                entity_type,
                entity_value,
                feedback_type=feedback_type,
                original_action=action,
                risk_score=risk_score,
                signals=signals,
                source=FeedbackSource.AUTO.value,
                notes=f"Auto-generated from {action}",
            )

        except Exception as e:
            logger.error("feedback_auto_failed", error=str(e))
            return {"success": False, "error": str(e)}

    # ═══════════════════════════════════════════════════════
    #  Utilities
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def clear_all(cls) -> None:
        """بيمسح كل بيانات الـ feedback."""
        client = cls.get_client()
        if not client:
            return

        try:
            cursor = 0
            while True:
                cursor, keys = await client.scan(
                    cursor=cursor,
                    match="fb:*",
                    count=100,
                )
                if keys:
                    await client.delete(*keys)
                if cursor == 0:
                    break

            logger.info("feedback_all_cleared")
        except Exception as e:
            logger.error("feedback_clear_all_failed", error=str(e))

    @classmethod
    async def close(cls) -> None:
        """بتقفل Redis."""
        if cls._redis_client:
            await cls._redis_client.close()
            cls._redis_client = None


# ─── Standalone functions ─────────────────────────────

async def record_feedback(
    entity_type: str,
    entity_value: str,
    **kwargs,
) -> Dict[str, Any]:
    """Shortcut for FeedbackLoop.record_feedback."""
    return await FeedbackLoop.record_feedback(
        entity_type, entity_value, **kwargs,
    )


async def get_stats() -> Dict[str, Any]:
    """Shortcut for FeedbackLoop.get_stats."""
    return await FeedbackLoop.get_stats()


async def get_threshold_adjustments(
    detector: Optional[str] = None,
    current_threshold: Optional[int] = None,
) -> Dict[str, Any]:
    """Shortcut for FeedbackLoop.get_threshold_adjustments."""
    return await FeedbackLoop.get_threshold_adjustments(
        detector, current_threshold,
    )