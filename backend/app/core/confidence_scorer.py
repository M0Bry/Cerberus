"""
Confidence Scorer — Multi-component confidence calculation for decisions.

بيوفر:
- Multi-component confidence scoring
- Detector agreement analysis
- Signal strength weighting
- Historical accuracy integration (من feedback_loop)
- Signal consistency detection
- Time-based consistency
- Confidence levels (low/medium/high/very_high)
- Decision recommendation
- High risk override
- Redis-backed caching

الفكرة:
- بدل ما ناخد قرار على risk_score واحد، بنستخدم confidence
- الـ confidence بتتكون من 5-6 مكونات
- كل مكون له وزن
- الناتج: 0.0 - 1.0 + recommendation

المكونات:
1. Risk Component: نسبة الخطورة (risk_score / 100)
2. Detector Agreement: هل الـ detectors متفقين؟
3. Signal Strength: قوة الإشارات
4. Historical Accuracy: دقة الـ detector (من feedback)
5. Signal Consistency: هل الإشارات متسقة؟
6. Signal Count: عدد الإشارات

High Risk Override:
- لو risk_score >= 90 → confidence >= 0.80 (block)
- لو risk_score >= 80 → confidence >= 0.70 (high)
- لو risk_score >= 70 → confidence >= 0.60 (challenge)

الاستخدام:
- auto_mitigation.py
- defense_service.py
- explainability.py
- anomaly_detection.py
"""

import json
import math
import time
from enum import Enum
from typing import Any, Dict, List, Optional

import redis.asyncio as redis
import structlog

from app.core.config import settings

logger = structlog.get_logger()


class ConfidenceLevel(str, Enum):
    """مستويات الثقة."""
    VERY_LOW = "very_low"      # 0.0 - 0.3
    LOW = "low"                # 0.3 - 0.5
    MEDIUM = "medium"          # 0.5 - 0.7
    HIGH = "high"              # 0.7 - 0.85
    VERY_HIGH = "very_high"    # 0.85 - 1.0


class ConfidenceScorer:
    """
    Multi-Component Confidence Scorer.

    الفكرة:
    - بنجمع confidence من عدة مصادر
    - بنستخدم weighted average
    - بنرجع score + level + recommendation
    """

    _redis_client: Optional[redis.Redis] = None

    # ─── Config ────────────────────────────────────────────
    CACHE_TTL = 300              # 5 دقائق

    # ─── Component Weights (مجموعها 1.0) ──────────────────
    WEIGHTS = {
        "risk": 0.30,              # وزن risk_score
        "detector_agreement": 0.25, # اتفاق detectors
        "signal_strength": 0.15,    # قوة الإشارات
        "historical_accuracy": 0.15, # دقة تاريخية
        "signal_consistency": 0.10,  # تناسق الإشارات
        "signal_count": 0.05,        # عدد الإشارات
    }

    # ─── Confidence Levels ────────────────────────────────
    LEVELS = {
        ConfidenceLevel.VERY_LOW: (0.0, 0.3),
        ConfidenceLevel.LOW: (0.3, 0.5),
        ConfidenceLevel.MEDIUM: (0.5, 0.7),
        ConfidenceLevel.HIGH: (0.7, 0.85),
        ConfidenceLevel.VERY_HIGH: (0.85, 1.01),
    }

    # ─── Signal Strength Map ──────────────────────────────
    SIGNAL_STRENGTH = {
        # Critical (0.9 - 1.0)
        "sql_injection": 1.0,
        "rce_attempt": 1.0,
        "beacon_pattern": 0.95,
        "c2_traffic": 0.95,
        "data_exfiltration": 0.95,
        "ransomware": 1.0,
        "webshell_detected": 0.95,
        "account_takeover": 0.9,

        # High (0.7 - 0.9)
        "bruteforce": 0.85,
        "credential_stuffing": 0.85,
        "malicious_payload": 0.85,
        "path_traversal": 0.8,
        "auth_bypass": 0.8,
        "known_bad_ip": 0.8,
        "tor_exit": 0.75,

        # Medium (0.4 - 0.7)
        "scraping": 0.6,
        "shared_ip": 0.6,
        "shared_device": 0.65,
        "high_velocity": 0.55,
        "stage_progression": 0.65,
        "dense_cluster": 0.6,
        "bridge_node": 0.55,

        # Low (0.0 - 0.4)
        "user_enumeration": 0.4,
        "unusual_hour": 0.35,
        "new_device": 0.4,
        "new_country": 0.45,
        "rate_spike": 0.3,
    }

    # ─── Signal Families ──────────────────────────────────
    SIGNAL_FAMILIES = {
        "injection": {"sql_injection", "rce_attempt", "path_traversal"},
        "auth": {"bruteforce", "credential_stuffing", "account_takeover", "auth_bypass"},
        "malware": {"malicious_payload", "webshell_detected", "ransomware", "beacon_pattern"},
        "network": {"known_bad_ip", "tor_exit", "c2_traffic", "data_exfiltration"},
        "behavioral": {"scraping", "user_enumeration", "high_velocity", "rate_spike"},
        "identity": {"new_device", "new_country", "shared_device", "shared_ip"},
    }

    # ─── Recommendation Thresholds ────────────────────────
    RECOMMENDATIONS = {
        "block": 0.75,
        "challenge": 0.60,
        "monitor": 0.40,
        "allow": 0.0,
    }

    # ─── High Risk Override Thresholds ────────────────────
    # لو risk_score عالي، ارفع الـ confidence للحد الأدنى
    HIGH_RISK_OVERRIDES = [
        (90, 0.80),   # risk >= 90 → confidence >= 0.80
        (80, 0.70),   # risk >= 80 → confidence >= 0.70
        (70, 0.60),   # risk >= 70 → confidence >= 0.60
    ]

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
                logger.error("confidence_scorer_redis_init_failed", error=str(e))
                return None
        return cls._redis_client

    @classmethod
    def _level_from_score(cls, score: float) -> ConfidenceLevel:
        """بيحوّل score لـ level."""
        for level, (low, high) in cls.LEVELS.items():
            if low <= score < high:
                return level
        return ConfidenceLevel.VERY_LOW

    @classmethod
    def _recommendation_from_score(cls, score: float) -> str:
        """بيرجع توصية بناءً على الـ score."""
        for action, threshold in cls.RECOMMENDATIONS.items():
            if score >= threshold:
                return action
        return "allow"

    # ═══════════════════════════════════════════════════════
    #  Component: Risk Score
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def _score_risk(risk_score: int) -> float:
        """بيحوّل risk_score (0-100) لـ confidence (0.0-1.0)."""
        if risk_score <= 0:
            return 0.0
        if risk_score >= 100:
            return 1.0
        return min(risk_score / 100.0, 1.0)

    # ═══════════════════════════════════════════════════════
    #  Component: Detector Agreement
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def _score_detector_agreement(
        detector_scores: Optional[Dict[str, float]],
    ) -> float:
        """
        بيحسب مدى اتفاق الـ detectors.

        Args:
            detector_scores: {detector_name: score} — score في [0, 1]

        Returns:
            0.0 (كلهم مختلفين) - 1.0 (كلهم متفقين)
        """
        if not detector_scores:
            return 0.3  # مفيش معلومات → default أقل

        scores = [
            max(0.0, min(1.0, float(s)))
            for s in detector_scores.values()
            if s is not None
        ]

        if len(scores) < 2:
            return 0.3

        # لو كلهم فوق 0.5 → اتفاق على تهديد
        # لو كلهم تحت 0.5 → اتفاق على safe
        # لو مخلوطين → uncertainty

        above = sum(1 for s in scores if s > 0.5)
        below = len(scores) - above

        # agreement ratio
        dominant = max(above, below)
        agreement_ratio = dominant / len(scores)

        # نطبّع: 0.5 → 0, 1.0 → 1
        normalized = (agreement_ratio - 0.5) * 2

        return max(0.0, min(normalized, 1.0))

    # ═══════════════════════════════════════════════════════
    #  Component: Signal Strength
    # ═══════════════════════════════════════════════════════

    @classmethod
    def _score_signal_strength(
        cls,
        signals: List[str],
    ) -> float:
        """
        بيحسب متوسط قوة الإشارات.

        Returns:
            0.0 - 1.0
        """
        if not signals:
            return 0.0

        strengths = []
        for sig in signals:
            sig_lower = sig.lower().strip()

            # مباشر
            if sig_lower in cls.SIGNAL_STRENGTH:
                strengths.append(cls.SIGNAL_STRENGTH[sig_lower])
                continue

            # partial match
            matched = False
            for pattern, strength in cls.SIGNAL_STRENGTH.items():
                if pattern in sig_lower:
                    strengths.append(strength)
                    matched = True
                    break

            if not matched:
                # default strength — أقل للـ unknown
                strengths.append(0.25)

        if not strengths:
            return 0.0

        # mean + bonus للأعلى
        mean_strength = sum(strengths) / len(strengths)
        max_strength = max(strengths)

        # 70% mean + 30% max
        return 0.7 * mean_strength + 0.3 * max_strength

    # ═══════════════════════════════════════════════════════
    #  Component: Historical Accuracy
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def _score_historical_accuracy(
        cls,
        detector: Optional[str] = None,
    ) -> float:
        """
        بيرجع دقة تاريخية من feedback_loop.

        Returns:
            0.0 - 1.0
        """
        try:
            from app.core.feedback_loop import FeedbackLoop

            if detector:
                stats = await FeedbackLoop._get_detector_stats(detector)
            else:
                stats = await FeedbackLoop.get_stats()

            if not stats.get("success"):
                return 0.3  # default أقل

            total = stats.get("total", 0)
            if total < 5:
                return 0.3  # عينة صغيرة → default أقل

            # accuracy من stats
            accuracy = stats.get("accuracy", 0.5)

            # precision
            precision = stats.get("precision", 0.5)

            # mean
            return (accuracy + precision) / 2

        except Exception as e:
            logger.debug("confidence_historical_failed", error=str(e))
            return 0.3

    # ═══════════════════════════════════════════════════════
    #  Component: Signal Consistency
    # ═══════════════════════════════════════════════════════

    @classmethod
    def _score_signal_consistency(
        cls,
        signals: List[str],
    ) -> float:
        """
        بيحسب مدى تناسق الإشارات.

        Returns:
            0.0 - 1.0
        """
        if not signals or len(signals) < 2:
            return 0.3  # single signal → default أقل

        sigs_lower = [s.lower().strip() for s in signals]

        # احسب عدد العائلات
        matched_families: Dict[str, int] = {}
        unmatched = 0

        for sig in sigs_lower:
            matched = False
            for family_name, family_signals in cls.SIGNAL_FAMILIES.items():
                # شوف لو الـ signal أو أي جزء منه في العائلة
                if any(fs in sig or sig in fs for fs in family_signals):
                    matched_families[family_name] = matched_families.get(
                        family_name, 0
                    ) + 1
                    matched = True
                    break

            if not matched:
                unmatched += 1

        total = len(sigs_lower)

        if not matched_families:
            return 0.3  # مفيش تطابق

        # نسبة الإشارات اللي في أكبر عائلة
        max_family_count = max(matched_families.values())
        max_ratio = max_family_count / total

        # لو 60%+ من نفس العائلة → consistent عالي
        if max_ratio >= 0.6:
            return 0.9  # consistent
        elif max_ratio >= 0.4:
            return 0.7
        else:
            # diverse — ممكن يكون coordinated (attack chain)
            return 0.5

    # ═══════════════════════════════════════════════════════
    #  Component: Signal Count
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def _score_signal_count(
        signals: List[str],
        *,
        max_expected: int = 5,
    ) -> float:
        """
        بيحسب score بناءً على عدد الإشارات.

        Returns:
            0.0 - 1.0
        """
        if not signals:
            return 0.0

        count = len(signals)

        if count <= 0:
            return 0.0
        if count >= max_expected:
            return 1.0

        # linear scaling
        return min(count / max_expected, 1.0)

    # ═══════════════════════════════════════════════════════
    #  Main Scoring
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def score(
        cls,
        *,
        risk_score: int,
        signals: Optional[List[str]] = None,
        detector_scores: Optional[Dict[str, float]] = None,
        detector: Optional[str] = None,
        use_cache: bool = False,
    ) -> Dict[str, Any]:
        """
        بيحسب confidence score شامل.

        Args:
            risk_score: 0-100 من detectors
            signals: قائمة signals
            detector_scores: {detector_name: score_0_to_1}
            detector: اسم الـ detector (للـ historical accuracy)
            use_cache: يستخدم cache؟

        Returns:
            dict فيه:
            - confidence_score: 0.0 - 1.0
            - confidence_level: level
            - components: تفصيل كل مكون
            - recommendation: block/challenge/monitor/allow
            - high_risk_override: bool
        """
        try:
            signals = signals or []
            detector_scores = detector_scores or {}

            # ─── 1. احسب كل مكون ───
            components: Dict[str, float] = {}

            components["risk"] = cls._score_risk(risk_score)
            components["detector_agreement"] = cls._score_detector_agreement(
                detector_scores
            )
            components["signal_strength"] = cls._score_signal_strength(signals)
            components["historical_accuracy"] = (
                await cls._score_historical_accuracy(detector)
            )
            components["signal_consistency"] = cls._score_signal_consistency(
                signals
            )
            components["signal_count"] = cls._score_signal_count(signals)

            # ─── 2. احسب weighted average ───
            total_weight = 0.0
            weighted_sum = 0.0

            for component_name, value in components.items():
                weight = cls.WEIGHTS.get(component_name, 0.0)
                weighted_sum += value * weight
                total_weight += weight

            if total_weight > 0:
                confidence_score = weighted_sum / total_weight
            else:
                confidence_score = 0.0

            # حدود
            confidence_score = max(0.0, min(confidence_score, 1.0))

            # ─── 2b. High Risk Override ───
            # لو risk_score عالي جداً، لازم القرار يكون حذر
            high_risk_override = False
            original_score = confidence_score

            for min_risk, min_confidence in cls.HIGH_RISK_OVERRIDES:
                if risk_score >= min_risk and confidence_score < min_confidence:
                    confidence_score = min_confidence
                    high_risk_override = True
                    break

            # ─── 3. level + recommendation ───
            level = cls._level_from_score(confidence_score)
            recommendation = cls._recommendation_from_score(confidence_score)

            # ─── 4. النتيجة ───
            result = {
                "success": True,
                "confidence_score": round(confidence_score, 4),
                "confidence_percentage": round(confidence_score * 100, 1),
                "confidence_level": level.value,
                "recommendation": recommendation,
                "high_risk_override": high_risk_override,
                "original_score": round(original_score, 4) if high_risk_override else None,
                "components": {
                    k: round(v, 4)
                    for k, v in components.items()
                },
                "weights": dict(cls.WEIGHTS),
                "inputs": {
                    "risk_score": risk_score,
                    "signals_count": len(signals),
                    "signals": signals[:10],
                    "detectors_count": len(detector_scores),
                    "detector": detector,
                },
                "scored_at": time.time(),
            }

            # ─── 5. Log ───
            if confidence_score >= 0.85:
                logger.warning(
                    "confidence_high",
                    score=round(confidence_score, 3),
                    level=level.value,
                    recommendation=recommendation,
                    risk_score=risk_score,
                    override=high_risk_override,
                )
            elif confidence_score <= 0.3:
                logger.debug(
                    "confidence_low",
                    score=round(confidence_score, 3),
                    level=level.value,
                )

            return result

        except Exception as e:
            logger.error("confidence_scoring_failed", error=str(e))
            return {"success": False, "error": str(e)}

    # ═══════════════════════════════════════════════════════
    #  Batch Scoring
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def score_batch(
        cls,
        items: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """بيقيّم مجموعة عناصر."""
        results = []
        for item in items:
            result = await cls.score(
                risk_score=item.get("risk_score", 0),
                signals=item.get("signals", []),
                detector_scores=item.get("detector_scores"),
                detector=item.get("detector"),
            )
            results.append(result)
        return results

    # ═══════════════════════════════════════════════════════
    #  Utilities
    # ═══════════════════════════════════════════════════════

    @classmethod
    def explain(cls, result: Dict[str, Any]) -> str:
        """بيدي شرح نصي لنتيجة الـ confidence."""
        if not result.get("success"):
            return "Confidence scoring failed"

        score = result["confidence_score"]
        level = result["confidence_level"]
        rec = result["recommendation"]
        components = result["components"]

        lines = [
            f"Confidence: {score:.2f} ({level})",
            f"Recommendation: {rec}",
        ]

        if result.get("high_risk_override"):
            lines.append(
                f"⚠️ High risk override: {result['original_score']:.2f} → {score:.2f}"
            )

        lines.append("Components:")

        # رتب المكونات حسب الأهمية
        for name, value in sorted(
            components.items(),
            key=lambda x: x[1],
            reverse=True,
        ):
            weight = cls.WEIGHTS.get(name, 0)
            lines.append(
                f"  • {name}: {value:.2f} (weight: {weight:.2f})"
            )

        return "\n".join(lines)

    @classmethod
    def get_config(cls) -> Dict[str, Any]:
        """بيرجع إعدادات الـ scorer."""
        return {
            "weights": dict(cls.WEIGHTS),
            "levels": {
                level.value: {"min": r[0], "max": r[1]}
                for level, r in cls.LEVELS.items()
            },
            "recommendations": dict(cls.RECOMMENDATIONS),
            "high_risk_overrides": cls.HIGH_RISK_OVERRIDES,
            "signal_strength_map": dict(cls.SIGNAL_STRENGTH),
            "signal_families": {
                name: list(sigs)
                for name, sigs in cls.SIGNAL_FAMILIES.items()
            },
        }

    @classmethod
    async def close(cls) -> None:
        """بتقفل Redis."""
        if cls._redis_client:
            await cls._redis_client.close()
            cls._redis_client = None


# ─── Standalone functions ─────────────────────────────

async def score(
    risk_score: int,
    signals: Optional[List[str]] = None,
    **kwargs,
) -> Dict[str, Any]:
    """Shortcut for ConfidenceScorer.score."""
    return await ConfidenceScorer.score(
        risk_score=risk_score,
        signals=signals,
        **kwargs,
    )


def explain(result: Dict[str, Any]) -> str:
    """Shortcut for ConfidenceScorer.explain."""
    return ConfidenceScorer.explain(result)