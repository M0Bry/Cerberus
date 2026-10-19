"""
Explainability — Human-readable explanations for decisions (XAI).

بيوفر:
- Decision explanations (نصية + structured)
- Factor attribution (ليه القرار اتخد)
- Confidence breakdown
- Signal contribution analysis
- Timeline reconstruction
- Alternative outcomes
- Multiple output formats (text, json, html)
- Template-based narratives
- Redis-backed explanation cache

الفكرة:
- بناخد كل بيانات القرار
- بنحللها ونرتبها
- بنطلع شرح مفهوم للبشر
- مناسب لـ:
  * Admin dashboards
  * Incident reports
  * Compliance (GDPR Article 22)
  * Debugging
  * ML monitoring

الاستخدام:
- defense_service.py
- admin endpoints
- report generation
- audit logs
"""

import json
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional

import redis.asyncio as redis
import structlog

from app.core.config import settings

logger = structlog.get_logger()


class Explainability:
    """
    Decision Explainability Engine.

    الفكرة:
    - بنجمع كل بيانات القرار
    - بنرتب العوامل حسب التأثير
    - بنولّد شرح نصي + structured
    """

    _redis_client: Optional[redis.Redis] = None

    # ─── Config ────────────────────────────────────────────
    CACHE_TTL = 86400 * 7        # 7 أيام
    MAX_EXPLANATIONS = 1000

    # ─── Redis Keys ───────────────────────────────────────
    EXPLANATIONS_KEY = "xai:explanations"
    EXPLANATION_KEY_PREFIX = "xai:explanation:"

    # ─── Factor Weight Display ────────────────────────────
    FACTOR_ICONS = {
        "critical": "🚨",
        "high": "⚠️",
        "medium": "⚡",
        "low": "ℹ️",
        "info": "📝",
        "positive": "✅",
        "negative": "❌",
    }

    # ─── Action Descriptions ──────────────────────────────
    ACTION_DESCRIPTIONS = {
        "allow": "Access granted",
        "monitor": "Access allowed with monitoring",
        "challenge": "Additional verification required",
        "rate_limit": "Rate limiting applied",
        "temp_block": "Temporarily blocked",
        "block": "Blocked",
    }

    # ─── Signal → Human-readable Description ─────────────
    SIGNAL_DESCRIPTIONS = {
        "sql_injection": "SQL injection attempt detected",
        "rce_attempt": "Remote code execution attempt",
        "beacon_pattern": "Command & control beacon pattern",
        "c2_traffic": "C2 traffic detected",
        "data_exfiltration": "Data exfiltration attempt",
        "ransomware": "Ransomware activity",
        "webshell_detected": "Webshell detected",
        "account_takeover": "Account takeover attempt",
        "bruteforce": "Brute force attack",
        "credential_stuffing": "Credential stuffing attack",
        "malicious_payload": "Malicious payload detected",
        "path_traversal": "Path traversal attempt",
        "auth_bypass": "Authentication bypass attempt",
        "known_bad_ip": "IP is on known threat lists",
        "tor_exit": "Connection from Tor exit node",
        "scraping": "Web scraping activity",
        "shared_ip": "IP shared by many users",
        "shared_device": "Device shared by many users",
        "high_velocity": "Unusually high request rate",
        "stage_progression": "Multi-stage attack progression",
        "dense_cluster": "Dense cluster of suspicious activity",
        "bridge_node": "Bridge node connecting suspicious entities",
        "user_enumeration": "Username enumeration detected",
        "unusual_hour": "Activity at unusual hour",
        "new_device": "New device detected",
        "new_country": "New country detected",
        "rate_spike": "Rate spike detected",
        "scraping_detector": "Scraping pattern detected",
        "ip_reputation": "Low IP reputation",
        "impossible_travel": "Impossible travel detected",
        "credential_reuse": "Credential reuse detected",
    }

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
                logger.error("explainability_redis_init_failed", error=str(e))
                return None
        return cls._redis_client

    @staticmethod
    def _explanation_key(explanation_id: str) -> str:
        return f"{Explainability.EXPLANATION_KEY_PREFIX}{explanation_id}"

    @classmethod
    def _generate_id(cls) -> str:
        """بيولّد ID فريد للشرح."""
        import hashlib
        seed = f"xai:{time.time()}:{id(object())}"
        return hashlib.sha256(seed.encode()).hexdigest()[:16]

    @classmethod
    def _describe_signal(cls, signal: str) -> str:
        """بيرجع وصف مفهوم للـ signal."""
        signal_lower = signal.lower().strip()

        # مباشر
        if signal_lower in cls.SIGNAL_DESCRIPTIONS:
            return cls.SIGNAL_DESCRIPTIONS[signal_lower]

        # partial match
        for pattern, description in cls.SIGNAL_DESCRIPTIONS.items():
            if pattern in signal_lower:
                return description

        # default
        return signal.replace("_", " ").title()

    @classmethod
    def _severity_icon(cls, severity: str) -> str:
        """بيرجع icon حسب الـ severity."""
        return cls.FACTOR_ICONS.get(severity.lower(), "•")

    # ═══════════════════════════════════════════════════════
    #  Factor Ranking
    # ═══════════════════════════════════════════════════════

    @classmethod
    def _rank_factors(
        cls,
        *,
        risk_score: int,
        signals: List[str],
        detector_scores: Optional[Dict[str, float]],
        confidence_components: Optional[Dict[str, float]],
    ) -> List[Dict[str, Any]]:
        """
        بيرتب العوامل حسب التأثير على القرار.

        Returns:
            قائمة factors مرتبة تنازلياً حسب الأهمية
        """
        factors: List[Dict[str, Any]] = []

        # ─── 1. Signals (الأهم) ───
        # كل signal له weight
        signal_weights = cls._get_signal_weights(signals)
        for signal, weight in signal_weights:
            # حدد الـ severity
            severity = cls._severity_from_weight(weight)

            factors.append({
                "type": "signal",
                "name": signal,
                "description": cls._describe_signal(signal),
                "weight": round(weight, 3),
                "severity": severity,
                "icon": cls._severity_icon(severity),
                "category": "detection",
            })

        # ─── 2. Detector agreement ───
        if detector_scores and len(detector_scores) > 1:
            agreement = cls._calc_agreement(detector_scores)

            if agreement > 0.7:
                factors.append({
                    "type": "consensus",
                    "name": "detector_agreement",
                    "description": f"All detectors agree (high confidence)",
                    "weight": agreement,
                    "severity": "positive",
                    "icon": cls._severity_icon("positive"),
                    "category": "consensus",
                })
            elif agreement < 0.3:
                factors.append({
                    "type": "disagreement",
                    "name": "detector_disagreement",
                    "description": f"Detectors disagree (low confidence)",
                    "weight": 1 - agreement,
                    "severity": "medium",
                    "icon": cls._severity_icon("medium"),
                    "category": "uncertainty",
                })

        # ─── 3. Risk score ───
        if risk_score >= 70:
            factors.append({
                "type": "risk",
                "name": "high_risk_score",
                "description": f"High overall risk score: {risk_score}/100",
                "weight": risk_score / 100.0,
                "severity": "high" if risk_score >= 85 else "medium",
                "icon": cls._severity_icon("high" if risk_score >= 85 else "medium"),
                "category": "risk",
            })
        elif risk_score >= 40:
            factors.append({
                "type": "risk",
                "name": "moderate_risk_score",
                "description": f"Moderate risk score: {risk_score}/100",
                "weight": risk_score / 100.0,
                "severity": "low",
                "icon": cls._severity_icon("low"),
                "category": "risk",
            })

        # ─── 4. Confidence components ───
        if confidence_components:
            # ابحث عن المكونات الضعيفة
            for name, value in confidence_components.items():
                if name == "risk":
                    continue  # already added

                if value < 0.3:
                    factors.append({
                        "type": "confidence",
                        "name": f"low_{name}",
                        "description": f"Low {name.replace('_', ' ')}: {value:.2f}",
                        "weight": 1 - value,
                        "severity": "medium",
                        "icon": cls._severity_icon("medium"),
                        "category": "confidence",
                    })

        # ─── 5. Sort by weight ───
        factors.sort(key=lambda x: x["weight"], reverse=True)

        return factors

    @staticmethod
    def _get_signal_weights(
        signals: List[str],
    ) -> List[tuple]:
        """بيرجع (signal, weight) مرتبة حسب الوزن."""
        try:
            from app.core.confidence_scorer import ConfidenceScorer

            weighted = []
            for sig in signals:
                sig_lower = sig.lower().strip()

                if sig_lower in ConfidenceScorer.SIGNAL_STRENGTH:
                    weight = ConfidenceScorer.SIGNAL_STRENGTH[sig_lower]
                else:
                    weight = 0.4  # default

                weighted.append((sig, weight))

            # رتب تنازلياً
            weighted.sort(key=lambda x: x[1], reverse=True)
            return weighted

        except Exception:
            return [(s, 0.5) for s in signals]

    @staticmethod
    def _severity_from_weight(weight: float) -> str:
        """بيحدد severity من الوزن."""
        if weight >= 0.85:
            return "critical"
        elif weight >= 0.7:
            return "high"
        elif weight >= 0.5:
            return "medium"
        elif weight >= 0.3:
            return "low"
        return "info"

    @staticmethod
    def _calc_agreement(detector_scores: Dict[str, float]) -> float:
        """بيحسب اتفاق الـ detectors."""
        scores = list(detector_scores.values())
        if len(scores) < 2:
            return 0.5

        above = sum(1 for s in scores if s > 0.5)
        below = len(scores) - above
        dominant = max(above, below)
        return dominant / len(scores)

    # ═══════════════════════════════════════════════════════
    #  Narrative Generation
    # ═══════════════════════════════════════════════════════

    @classmethod
    def _build_narrative(
        cls,
        *,
        entity: str,
        action: str,
        risk_score: int,
        confidence_score: float,
        confidence_level: str,
        signals: List[str],
        top_factors: List[Dict[str, Any]],
        high_risk_override: bool = False,
    ) -> str:
        """بيبني شرح نصي كامل."""
        lines: List[str] = []

        # ─── Header ───
        action_desc = cls.ACTION_DESCRIPTIONS.get(action, action)
        lines.append(f"📋 Decision: {action_desc} for {entity}")
        lines.append("")

        # ─── Summary ───
        severity_icon = cls._severity_icon(
            "critical" if risk_score >= 85 else
            "high" if risk_score >= 70 else
            "medium" if risk_score >= 50 else
            "low"
        )

        lines.append(
            f"{severity_icon} Risk Score: {risk_score}/100 "
            f"(Confidence: {confidence_score:.0%} - {confidence_level})"
        )

        if high_risk_override:
            lines.append(
                f"   ⚠️ High-risk override applied "
                f"(confidence elevated to {confidence_score:.0%})"
            )

        lines.append("")

        # ─── Top Factors ───
        if top_factors:
            lines.append(f"🔍 Key Factors ({len(top_factors)}):")

            for i, factor in enumerate(top_factors[:5], 1):
                icon = factor.get("icon", "•")
                desc = factor.get("description", factor.get("name"))
                weight = factor.get("weight", 0)

                lines.append(
                    f"   {i}. {icon} {desc} "
                    f"(impact: {weight:.0%})"
                )

            if len(top_factors) > 5:
                lines.append(f"   ... and {len(top_factors) - 5} more factors")

        # ─── Explanation ───
        lines.append("")
        lines.append("💡 Reasoning:")

        if action in ("block", "temp_block"):
            if risk_score >= 85:
                lines.append(
                    "   Multiple critical security signals indicate "
                    "an active attack. Immediate blocking is required."
                )
            elif risk_score >= 70:
                lines.append(
                    "   Several high-severity signals detected. "
                    "Blocking to prevent potential damage."
                )
            else:
                lines.append(
                    "   Suspicious activity detected. "
                    "Blocking as precautionary measure."
                )
        elif action == "challenge":
            lines.append(
                "   Moderate risk detected. Requesting additional "
                "verification to confirm legitimacy."
            )
        elif action == "rate_limit":
            lines.append(
                "   Unusual request rate detected. Applying rate limiting "
                "to prevent abuse while allowing normal access."
            )
        elif action == "monitor":
            lines.append(
                "   Low-level signals detected. Allowing access but "
                "increasing monitoring for further analysis."
            )
        else:
            lines.append(
                "   No significant security concerns. "
                "Access granted under normal conditions."
            )

        return "\n".join(lines)

    # ═══════════════════════════════════════════════════════
    #  Main Explain
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def explain_decision(
        cls,
        *,
        entity: str,
        action: str,
        risk_score: int,
        signals: Optional[List[str]] = None,
        detector_scores: Optional[Dict[str, float]] = None,
        confidence_result: Optional[Dict[str, Any]] = None,
        additional_context: Optional[Dict[str, Any]] = None,
        save: bool = True,
    ) -> Dict[str, Any]:
        """
        بيولّد شرح كامل للقرار.

        Args:
            entity: الكيان (مثلاً "ip:45.33.32.156")
            action: القرار (allow/block/...)
            risk_score: 0-100
            signals: قائمة signals
            detector_scores: {detector: score}
            confidence_result: نتيجة ConfidenceScorer (اختياري)
            additional_context: معلومات إضافية
            save: يحفظ الشرح في Redis؟

        Returns:
            dict فيه:
            - explanation_id: ID فريد
            - narrative: شرح نصي
            - summary: ملخص قصير
            - top_factors: أهم العوامل
            - confidence: تفاصيل الثقة
            - structured: بيانات structured
        """
        try:
            signals = signals or []
            detector_scores = detector_scores or {}
            additional_context = additional_context or {}

            # ─── 1. استخرج الـ confidence info ───
            if confidence_result and confidence_result.get("success"):
                confidence_score = confidence_result.get("confidence_score", 0.5)
                confidence_level = confidence_result.get("confidence_level", "medium")
                confidence_components = confidence_result.get("components", {})
                recommendation = confidence_result.get("recommendation", action)
                high_risk_override = confidence_result.get("high_risk_override", False)
            else:
                # default: نقدر نحسبها لو مش متوفرة
                confidence_score = risk_score / 100.0
                confidence_level = (
                    "very_high" if confidence_score >= 0.85 else
                    "high" if confidence_score >= 0.7 else
                    "medium" if confidence_score >= 0.5 else
                    "low" if confidence_score >= 0.3 else
                    "very_low"
                )
                confidence_components = {}
                recommendation = action
                high_risk_override = False

            # ─── 2. احسب الـ factors ───
            factors = cls._rank_factors(
                risk_score=risk_score,
                signals=signals,
                detector_scores=detector_scores,
                confidence_components=confidence_components,
            )

            # ─── 3. ولّد الـ narrative ───
            narrative = cls._build_narrative(
                entity=entity,
                action=action,
                risk_score=risk_score,
                confidence_score=confidence_score,
                confidence_level=confidence_level,
                signals=signals,
                top_factors=factors,
                high_risk_override=high_risk_override,
            )

            # ─── 4. Summary ───
            if action in ("block", "temp_block"):
                summary = (
                    f"Blocked {entity} due to "
                    f"{'critical' if risk_score >= 85 else 'high'}-risk signals"
                )
            elif action == "challenge":
                summary = f"Challenging {entity} for additional verification"
            elif action == "rate_limit":
                summary = f"Rate limiting {entity}"
            elif action == "monitor":
                summary = f"Monitoring {entity} for further analysis"
            else:
                summary = f"Allowed {entity}"

            # ─── 5. Structured explanation ───
            structured = {
                "entity": entity,
                "action": action,
                "action_description": cls.ACTION_DESCRIPTIONS.get(action, action),
                "risk_score": risk_score,
                "confidence": {
                    "score": round(confidence_score, 4),
                    "level": confidence_level,
                    "components": confidence_components,
                    "high_risk_override": high_risk_override,
                },
                "signals": {
                    "total": len(signals),
                    "list": signals,
                    "descriptions": [
                        cls._describe_signal(s) for s in signals
                    ],
                },
                "detectors": detector_scores,
                "factors": factors,
                "top_factor": factors[0] if factors else None,
                "recommendation": recommendation,
                "context": additional_context,
            }

            # ─── 6. ID ───
            explanation_id = cls._generate_id()

            result = {
                "success": True,
                "explanation_id": explanation_id,
                "entity": entity,
                "action": action,
                "summary": summary,
                "narrative": narrative,
                "top_factors": factors[:5],  # أول 5
                "all_factors_count": len(factors),
                "confidence": {
                    "score": round(confidence_score, 4),
                    "level": confidence_level,
                },
                "structured": structured,
                "generated_at": time.time(),
            }

            # ─── 7. Save ───
            if save:
                await cls._save_explanation(explanation_id, result)

            # ─── 8. Log ───
            logger.info(
                "decision_explained",
                explanation_id=explanation_id,
                entity=entity,
                action=action,
                risk_score=risk_score,
                factors_count=len(factors),
            )

            return result

        except Exception as e:
            logger.error("explainability_failed", error=str(e))
            return {"success": False, "error": str(e)}

    @classmethod
    async def _save_explanation(
        cls,
        explanation_id: str,
        explanation: Dict[str, Any],
    ) -> None:
        """بيحفظ الشرح في Redis."""
        client = cls.get_client()
        if not client:
            return

        try:
            # 1. خزّن الشرح
            key = cls._explanation_key(explanation_id)
            await client.set(
                key,
                json.dumps(explanation, default=str),
                ex=cls.CACHE_TTL,
            )

            # 2. أضف للـ list
            await client.lpush(cls.EXPLANATIONS_KEY, explanation_id)
            await client.ltrim(cls.EXPLANATIONS_KEY, 0, cls.MAX_EXPLANATIONS - 1)
            await client.expire(cls.EXPLANATIONS_KEY, cls.CACHE_TTL)

        except Exception as e:
            logger.debug("explanation_save_failed", error=str(e))

    # ═══════════════════════════════════════════════════════
    #  Retrieval
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def get_explanation(
        cls,
        explanation_id: str,
    ) -> Optional[Dict[str, Any]]:
        """بيرجع شرح معين بـ ID."""
        client = cls.get_client()
        if not client:
            return None

        try:
            key = cls._explanation_key(explanation_id)
            raw = await client.get(key)

            if not raw:
                return None

            return json.loads(raw)

        except Exception as e:
            logger.error("explanation_get_failed", error=str(e))
            return None

    @classmethod
    async def get_recent_explanations(
        cls,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """بيرجع آخر الشروحات."""
        client = cls.get_client()
        if not client:
            return []

        try:
            ids = await client.lrange(cls.EXPLANATIONS_KEY, 0, limit - 1)

            explanations = []
            for eid in ids:
                explanation = await cls.get_explanation(eid)
                if explanation:
                    explanations.append(explanation)

            return explanations

        except Exception as e:
            logger.error("explanation_recent_failed", error=str(e))
            return []

    # ═══════════════════════════════════════════════════════
    #  Output Formats
    # ═══════════════════════════════════════════════════════

    @classmethod
    def to_text(
        cls,
        explanation: Dict[str, Any],
    ) -> str:
        """بيرجع الشرح كنص."""
        if not explanation.get("success"):
            return "Explanation failed"

        return explanation.get("narrative", "")

    @classmethod
    def to_json(
        cls,
        explanation: Dict[str, Any],
        *,
        pretty: bool = True,
    ) -> str:
        """بيرجع الشرح كـ JSON."""
        try:
            structured = explanation.get("structured", {})
            return json.dumps(
                structured,
                indent=2 if pretty else None,
                ensure_ascii=False,
                default=str,
            )
        except Exception:
            return "{}"

    @classmethod
    def to_html(
        cls,
        explanation: Dict[str, Any],
    ) -> str:
        """بيرجع الشرح كـ HTML."""
        if not explanation.get("success"):
            return "<p>Explanation failed</p>"

        structured = explanation.get("structured", {})
        factors = structured.get("factors", [])[:5]

        factors_html = ""
        for f in factors:
            icon = f.get("icon", "•")
            desc = f.get("description", "")
            weight = f.get("weight", 0)
            factors_html += f"""
            <li class="factor">
                <span class="icon">{icon}</span>
                <span class="desc">{desc}</span>
                <span class="weight">{weight:.0%}</span>
            </li>
            """

        return f"""
        <div class="explanation">
            <h3>{structured.get('action_description', 'Decision')}</h3>
            <p class="entity">{structured.get('entity', '')}</p>
            <div class="scores">
                <span>Risk: {structured.get('risk_score', 0)}/100</span>
                <span>Confidence: {structured.get('confidence', {}).get('score', 0):.0%}</span>
            </div>
            <h4>Top Factors:</h4>
            <ul class="factors">{factors_html}</ul>
        </div>
        """

    # ═══════════════════════════════════════════════════════
    #  Stats
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def get_stats(cls) -> Dict[str, Any]:
        """بيرجع إحصائيات الـ explainability."""
        client = cls.get_client()
        if not client:
            return {"success": False, "error": "redis_unavailable"}

        try:
            total_ids = await client.llen(cls.EXPLANATIONS_KEY)

            # جيب عينة عشان نحلل
            recent = await cls.get_recent_explanations(limit=100)

            action_counts: Dict[str, int] = defaultdict(int)
            level_counts: Dict[str, int] = defaultdict(int)

            for exp in recent:
                structured = exp.get("structured", {})
                action = structured.get("action", "unknown")
                action_counts[action] += 1

                level = structured.get("confidence", {}).get("level", "unknown")
                level_counts[level] += 1

            return {
                "success": True,
                "total_explanations": total_ids,
                "analyzed_sample": len(recent),
                "actions_distribution": dict(action_counts),
                "confidence_levels_distribution": dict(level_counts),
            }

        except Exception as e:
            logger.error("explainability_stats_failed", error=str(e))
            return {"success": False, "error": str(e)}

    # ═══════════════════════════════════════════════════════
    #  Utilities
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def clear_all(cls) -> None:
        """بيمسح كل الشروحات."""
        client = cls.get_client()
        if not client:
            return

        try:
            cursor = 0
            while True:
                cursor, keys = await client.scan(
                    cursor=cursor,
                    match="xai:*",
                    count=100,
                )
                if keys:
                    await client.delete(*keys)
                if cursor == 0:
                    break

            logger.info("explainability_all_cleared")
        except Exception as e:
            logger.error("explainability_clear_all_failed", error=str(e))

    @classmethod
    async def close(cls) -> None:
        """بتقفل Redis."""
        if cls._redis_client:
            await cls._redis_client.close()
            cls._redis_client = None


# ─── Standalone functions ─────────────────────────────

async def explain_decision(
    entity: str,
    action: str,
    risk_score: int,
    **kwargs,
) -> Dict[str, Any]:
    """Shortcut for Explainability.explain_decision."""
    return await Explainability.explain_decision(
        entity=entity,
        action=action,
        risk_score=risk_score,
        **kwargs,
    )


def to_text(explanation: Dict[str, Any]) -> str:
    """Shortcut for Explainability.to_text."""
    return Explainability.to_text(explanation)


def to_json(explanation: Dict[str, Any], **kwargs) -> str:
    """Shortcut for Explainability.to_json."""
    return Explainability.to_json(explanation, **kwargs)


def to_html(explanation: Dict[str, Any]) -> str:
    """Shortcut for Explainability.to_html."""
    return Explainability.to_html(explanation)