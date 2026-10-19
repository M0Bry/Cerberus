"""
Attack Chain — Multi-stage attack detection & correlation.

بيوفر:
- Multi-stage attack detection (recon → exploit → persist → exfil)
- Signal correlation (يربط signals من detectors مختلفة)
- Attack timeline (تسلسل زمني للأحداث)
- Kill chain mapping (Lockheed Martin framework)
- Attack narrative generation
- Redis-backed
- Stage detection heuristics

الفكرة:
- الهجمات الحقيقية بتتكون من stages
- كل stage ليها indicators
- بنربط الـ signals من كل الـ detectors
- لو فيه تسلسل منطقي → attack chain

الـ Kill Chain Stages:
1. Reconnaissance (استطلاع)
2. Weaponization (تجهيز)
3. Delivery (تسليم)
4. Exploitation (استغلال)
5. Installation (تثبيت)
6. Command & Control (C2)
7. Actions on Objectives (تنفيذ)

الاستخدام:
- abuse_detector.py
- auto_mitigation.py
- notifier.py
- explainability.py
- defense_service.py
"""

import json
import math
import time
from collections import defaultdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

import redis.asyncio as redis
import structlog

from app.core.config import settings

logger = structlog.get_logger()


class AttackStage(str, Enum):
    """مراحل الـ attack chain."""
    RECONNAISSANCE = "reconnaissance"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    C2 = "c2"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"
    UNKNOWN = "unknown"


class AttackChain:
    """
    Attack Chain Analyzer.

    الفكرة:
    - نسجل signals من كل الـ detectors
    - نربطهم بـ entity (IP, user, session)
    - نحلل التسلسل الزمني
    - نكشف الـ attack chain
    """

    _redis_client: Optional[redis.Redis] = None

    # ─── Config ────────────────────────────────────────────
    CHAIN_TTL = 86400 * 7        # 7 أيام
    WINDOW_SECONDS = 3600        # ساعة للربط
    MAX_SIGNALS_PER_CHAIN = 100

    # ─── Stage Weights ────────────────────────────────────
    # كل stage بيدي risk weight
    STAGE_WEIGHTS = {
        AttackStage.RECONNAISSANCE: 15,
        AttackStage.DELIVERY: 30,
        AttackStage.EXPLOITATION: 50,
        AttackStage.INSTALLATION: 60,
        AttackStage.C2: 75,
        AttackStage.EXFILTRATION: 85,
        AttackStage.IMPACT: 90,
        AttackStage.UNKNOWN: 10,
    }

    # ─── Signal → Stage Mapping ───────────────────────────
    # كل signal نوع بيتم rabt لـ stage
    SIGNAL_TO_STAGE = {
        # Reconnaissance
        "scraping": AttackStage.RECONNAISSANCE,
        "enumeration": AttackStage.RECONNAISSANCE,
        "scanning": AttackStage.RECONNAISSANCE,
        "port_scan": AttackStage.RECONNAISSANCE,
        "dir_bruteforce": AttackStage.RECONNAISSANCE,
        "user_enumeration": AttackStage.RECONNAISSANCE,

        # Delivery
        "payload_detected": AttackStage.DELIVERY,
        "malicious_payload": AttackStage.DELIVERY,
        "suspicious_upload": AttackStage.DELIVERY,
        "phishing_attempt": AttackStage.DELIVERY,
        "malicious_file": AttackStage.DELIVERY,

        # Exploitation
        "input_validation_failed": AttackStage.EXPLOITATION,
        "sql_injection": AttackStage.EXPLOITATION,
        "xss_attempt": AttackStage.EXPLOITATION,
        "rce_attempt": AttackStage.EXPLOITATION,
        "path_traversal": AttackStage.EXPLOITATION,
        "auth_bypass": AttackStage.EXPLOITATION,
        "bruteforce": AttackStage.EXPLOITATION,
        "credential_stuffing": AttackStage.EXPLOITATION,
        "account_takeover": AttackStage.EXPLOITATION,

        # Installation
        "persistence_attempt": AttackStage.INSTALLATION,
        "backdoor_upload": AttackStage.INSTALLATION,
        "webshell_detected": AttackStage.INSTALLATION,
        "scheduled_task": AttackStage.INSTALLATION,

        # C2
        "beacon_pattern": AttackStage.C2,
        "c2_traffic": AttackStage.C2,
        "periodic_callback": AttackStage.C2,
        "dns_tunneling": AttackStage.C2,

        # Exfiltration
        "data_exfiltration": AttackStage.EXFILTRATION,
        "large_upload": AttackStage.EXFILTRATION,
        "suspicious_download": AttackStage.EXFILTRATION,
        "bulk_data_access": AttackStage.EXFILTRATION,

        # Impact
        "ransomware": AttackStage.IMPACT,
        "data_destruction": AttackStage.IMPACT,
        "defacement": AttackStage.IMPACT,
        "service_disruption": AttackStage.IMPACT,

        # Generic (بنصنفهم حسب الوزن)
        "high_velocity": AttackStage.EXPLOITATION,
        "shared_ip": AttackStage.EXPLOITATION,
        "shared_device": AttackStage.EXPLOITATION,
        "known_bad_ip": AttackStage.DELIVERY,
        "tor_exit": AttackStage.DELIVERY,
        "blocked_country": AttackStage.DELIVERY,
        "dense_cluster": AttackStage.EXPLOITATION,
        "bridge_node": AttackStage.C2,
    }

    # ─── Chain Weights ────────────────────────────────────
    WEIGHTS = {
        "multi_stage": 40,          # 3+ stages مختلفة
        "stage_progression": 50,    # تقدم من stage لأعلى
        "rapid_progression": 35,    # تقدم سريع
        "high_severity": 45,        # signals عالية الخطورة
        "many_signals": 30,         # signals كتير
        "repeated_stage": 20,       # نفس stage بتتكرر
    }

    # ─── Risk Thresholds ──────────────────────────────────
    THRESHOLDS = {
        "low": 30,
        "medium": 50,
        "high": 70,
        "critical": 85,
    }

    # ─── Stage Order (للـ progression) ────────────────────
    STAGE_ORDER = [
        AttackStage.RECONNAISSANCE,
        AttackStage.DELIVERY,
        AttackStage.EXPLOITATION,
        AttackStage.INSTALLATION,
        AttackStage.C2,
        AttackStage.EXFILTRATION,
        AttackStage.IMPACT,
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
                logger.error("attack_chain_redis_init_failed", error=str(e))
                return None
        return cls._redis_client

    @staticmethod
    def _chain_key(entity_type: str, entity_value: str) -> str:
        """Key للـ attack chain."""
        return f"ac:chain:{entity_type}:{entity_value}"

    @staticmethod
    def _signals_key(entity_type: str, entity_value: str) -> str:
        """Key للـ signals."""
        return f"ac:signals:{entity_type}:{entity_value}"

    @staticmethod
    def _classify_signal(signal_type: str) -> AttackStage:
        """بيصنف signal لـ stage."""
        signal_lower = signal_type.lower().strip()

        # 1. مباشر
        if signal_lower in AttackChain.SIGNAL_TO_STAGE:
            return AttackChain.SIGNAL_TO_STAGE[signal_lower]

        # 2. Partial match
        for pattern, stage in AttackChain.SIGNAL_TO_STAGE.items():
            if pattern in signal_lower:
                return stage

        return AttackStage.UNKNOWN

    # ═══════════════════════════════════════════════════════
    #  Signal Recording
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def record_signal(
        cls,
        entity_type: str,
        entity_value: str,
        signal_type: str,
        *,
        severity: str = "medium",
        details: Optional[Dict[str, Any]] = None,
        source: str = "unknown",
        timestamp: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        بيسجل signal في الـ attack chain.

        Args:
            entity_type: نوع الكيان (ip/user/session/device)
            entity_value: قيمة الكيان
            signal_type: نوع الإشارة (e.g. "bruteforce", "sql_injection")
            severity: level (low/medium/high/critical)
            details: تفاصيل إضافية
            source: مصدر الإشارة (detector name)
            timestamp: وقت الحدث

        Returns:
            dict فيه success + stage
        """
        client = cls.get_client()
        if not client:
            return {"success": False, "error": "redis_unavailable"}

        try:
            if not entity_type or not entity_value or not signal_type:
                return {"success": False, "error": "missing_fields"}

            now = timestamp or time.time()

            # صنّف الـ signal
            stage = cls._classify_signal(signal_type)

            signal_data = {
                "timestamp": now,
                "signal_type": signal_type,
                "stage": stage.value,
                "severity": severity,
                "source": source,
                "details": details or {},
            }

            # 1. خزّن signal في list
            signals_key = cls._signals_key(entity_type, entity_value)
            await client.lpush(
                signals_key,
                json.dumps(signal_data),
            )
            await client.ltrim(signals_key, 0, cls.MAX_SIGNALS_PER_CHAIN - 1)
            await client.expire(signals_key, cls.CHAIN_TTL)

            # 2. سجل في chain metadata
            chain_key = cls._chain_key(entity_type, entity_value)
            await client.hincrby(chain_key, "total_signals", 1)
            await client.hincrby(chain_key, f"stage:{stage.value}", 1)
            await client.hset(chain_key, "last_signal", json.dumps({
                "type": signal_type,
                "stage": stage.value,
                "severity": severity,
            }))
            await client.hset(chain_key, "last_updated", str(now))
            if not await client.hexists(chain_key, "started_at"):
                await client.hset(chain_key, "started_at", str(now))
            await client.expire(chain_key, cls.CHAIN_TTL)

            logger.info(
                "attack_chain_signal_recorded",
                entity=f"{entity_type}:{entity_value}",
                signal=signal_type,
                stage=stage.value,
                severity=severity,
            )

            return {
                "success": True,
                "entity": f"{entity_type}:{entity_value}",
                "stage": stage.value,
                "signal_type": signal_type,
            }

        except Exception as e:
            logger.error("attack_chain_record_failed", error=str(e))
            return {"success": False, "error": str(e)}

    # ═══════════════════════════════════════════════════════
    #  Analysis
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def get_signals(
        cls,
        entity_type: str,
        entity_value: str,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """بيرجع كل الـ signals للكيان."""
        client = cls.get_client()
        if not client:
            return []

        try:
            signals_key = cls._signals_key(entity_type, entity_value)
            raw_list = await client.lrange(signals_key, 0, limit - 1)

            signals = []
            for raw in raw_list:
                try:
                    signals.append(json.loads(raw))
                except json.JSONDecodeError:
                    continue

            # رتب من الأقدم للأحدث
            signals.sort(key=lambda x: x.get("timestamp", 0))
            return signals

        except Exception as e:
            logger.error("attack_chain_get_signals_failed", error=str(e))
            return []

    @classmethod
    async def _detect_stage_progression(
        cls,
        signals: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        بيكشف التقدم في الـ stages.

        (يعني كل signal بعد مرحلة سابقة)
        """
        if len(signals) < 2:
            return {"detected": False, "confidence": 0}

        # رتب حسب الوقت
        sorted_signals = sorted(signals, key=lambda x: x.get("timestamp", 0))

        stage_indices: List[int] = []
        for sig in sorted_signals:
            stage_str = sig.get("stage", "unknown")
            try:
                stage = AttackStage(stage_str)
                if stage in cls.STAGE_ORDER:
                    stage_indices.append(cls.STAGE_ORDER.index(stage))
            except ValueError:
                continue

        if len(stage_indices) < 2:
            return {"detected": False, "confidence": 0}

        # احسب التقدم (increasing sequence)
        progressions = 0
        for i in range(1, len(stage_indices)):
            if stage_indices[i] > stage_indices[i - 1]:
                progressions += 1

        # نسبة التقدم
        progression_ratio = progressions / (len(stage_indices) - 1)

        if progression_ratio >= 0.6 and progressions >= 2:
            confidence = min(
                cls.WEIGHTS["stage_progression"]
                + int(progression_ratio * 30),
                100,
            )

            return {
                "detected": True,
                "confidence": confidence,
                "details": {
                    "progressions": progressions,
                    "total_transitions": len(stage_indices) - 1,
                    "progression_ratio": round(progression_ratio, 2),
                    "stages_sequence": [
                        cls.STAGE_ORDER[i].value for i in stage_indices
                    ],
                },
            }

        return {"detected": False, "confidence": 0}

    @classmethod
    async def _detect_rapid_progression(
        cls,
        signals: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        بيكشف التقدم السريع (كل الـ stages في وقت قصير).
        """
        if len(signals) < 3:
            return {"detected": False, "confidence": 0}

        sorted_signals = sorted(signals, key=lambda x: x.get("timestamp", 0))

        # احسب المدة الإجمالية
        first_ts = sorted_signals[0].get("timestamp", 0)
        last_ts = sorted_signals[-1].get("timestamp", 0)
        duration = last_ts - first_ts

        if duration <= 0:
            duration = 1.0

        # كم stage مختلفة في المدة دي؟
        unique_stages = set(
            s.get("stage", "unknown") for s in sorted_signals
        )
        unique_stages.discard("unknown")

        if len(unique_stages) < 3:
            return {"detected": False, "confidence": 0}

        # لو فيه 3+ stages في أقل من 10 دقايق → rapid
        stages_per_minute = len(unique_stages) / (duration / 60)

        if duration <= 600 and len(unique_stages) >= 3:
            confidence = min(
                cls.WEIGHTS["rapid_progression"]
                + (len(unique_stages) - 3) * 5,
                100,
            )

            return {
                "detected": True,
                "confidence": confidence,
                "details": {
                    "duration_seconds": int(duration),
                    "unique_stages": len(unique_stages),
                    "stages_per_minute": round(stages_per_minute, 2),
                },
            }

        return {"detected": False, "confidence": 0}

    @classmethod
    async def analyze(
        cls,
        entity_type: str,
        entity_value: str,
        *,
        window_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        تحليل شامل للـ attack chain.

        Args:
            entity_type: نوع الكيان
            entity_value: قيمة الكيان
            window_seconds: نافذة زمنية (اختياري)

        Returns:
            dict فيه:
            - is_attack_chain: bool
            - risk_score: 0-100
            - level: clean/low/medium/high/critical
            - stages: dict
            - signals: list
            - narrative: str
            - details: تفاصيل
        """
        try:
            if not entity_type or not entity_value:
                return {"success": False, "error": "missing_entity_info"}

            # ─── جيب الـ signals ───
            signals = await cls.get_signals(entity_type, entity_value, limit=100)

            # فلتر حسب النافذة
            if window_seconds:
                cutoff = time.time() - window_seconds
                signals = [
                    s for s in signals
                    if s.get("timestamp", 0) >= cutoff
                ]

            if not signals:
                return {
                    "success": True,
                    "entity": f"{entity_type}:{entity_value}",
                    "is_attack_chain": False,
                    "risk_score": 0,
                    "level": "clean",
                    "stages": {},
                    "signals": [],
                    "signal_count": 0,
                    "narrative": "No signals recorded",
                    "details": {},
                }

            # ─── 1. احسب stats ───
            stage_counts: Dict[str, int] = defaultdict(int)
            severity_counts: Dict[str, int] = defaultdict(int)
            signal_type_counts: Dict[str, int] = defaultdict(int)

            for sig in signals:
                stage = sig.get("stage", "unknown")
                severity = sig.get("severity", "medium")
                sig_type = sig.get("signal_type", "unknown")

                stage_counts[stage] += 1
                severity_counts[severity] += 1
                signal_type_counts[sig_type] += 1

            unique_stages = [s for s in stage_counts if s != "unknown"]
            n_unique_stages = len(unique_stages)

            # ─── 2. احسب risk score من stage weights ───
            total_score = 0
            signals_list: List[str] = []
            details: Dict[str, Any] = {}

            # Base: أعلى stage weight
            max_stage_weight = 0
            for stage_str in unique_stages:
                try:
                    stage = AttackStage(stage_str)
                    weight = cls.STAGE_WEIGHTS.get(stage, 0)
                    max_stage_weight = max(max_stage_weight, weight)
                except ValueError:
                    continue

            total_score += max_stage_weight

            # Multi-stage bonus
            if n_unique_stages >= 3:
                signals_list.append("multi_stage_attack")
                total_score += cls.WEIGHTS["multi_stage"]
                details["unique_stages"] = n_unique_stages

            # Many signals
            if len(signals) >= 10:
                signals_list.append("many_signals")
                total_score += cls.WEIGHTS["many_signals"]

            # High severity signals
            critical_count = severity_counts.get("critical", 0)
            high_count = severity_counts.get("high", 0)

            if critical_count >= 1:
                signals_list.append("critical_severity")
                total_score += cls.WEIGHTS["high_severity"]
                details["critical_signals"] = critical_count

            if high_count >= 3:
                signals_list.append("many_high_severity")
                total_score += cls.WEIGHTS["high_severity"] // 2

            # ─── 3. Stage progression ───
            progression = await cls._detect_stage_progression(signals)
            if progression["detected"]:
                signals_list.append("stage_progression")
                total_score += progression["confidence"]
                details["progression"] = progression["details"]

            # ─── 4. Rapid progression ───
            rapid = await cls._detect_rapid_progression(signals)
            if rapid["detected"]:
                signals_list.append("rapid_progression")
                total_score += rapid["confidence"]
                details["rapid"] = rapid["details"]

            # ─── 5. Risk score ───
            risk_score = min(int(math.sqrt(total_score) * 10), 100)

            # ─── 6. Level ───
            level = "clean"
            if risk_score >= cls.THRESHOLDS["critical"]:
                level = "critical"
            elif risk_score >= cls.THRESHOLDS["high"]:
                level = "high"
            elif risk_score >= cls.THRESHOLDS["medium"]:
                level = "medium"
            elif risk_score >= cls.THRESHOLDS["low"]:
                level = "low"

            # ─── 7. is_attack_chain ───
            # attack chain = multi-stage مع progression
            is_attack_chain = (
                n_unique_stages >= 2
                and (
                    "stage_progression" in signals_list
                    or "rapid_progression" in signals_list
                    or "multi_stage_attack" in signals_list
                )
            )

            # ─── 8. Narrative ───
            narrative = cls._build_narrative(
                signals, stage_counts, signal_type_counts
            )

            if is_attack_chain:
                logger.warning(
                    "attack_chain_detected",
                    entity=f"{entity_type}:{entity_value}",
                    risk_score=risk_score,
                    level=level,
                    unique_stages=n_unique_stages,
                    signals=signals_list,
                )

            return {
                "success": True,
                "entity": f"{entity_type}:{entity_value}",
                "is_attack_chain": is_attack_chain,
                "risk_score": risk_score,
                "level": level,
                "signals": signals_list,
                "signal_count": len(signals_list),
                "stages": dict(stage_counts),
                "unique_stages": n_unique_stages,
                "total_signals": len(signals),
                "severity_breakdown": dict(severity_counts),
                "top_signal_types": sorted(
                    signal_type_counts.items(),
                    key=lambda x: x[1],
                    reverse=True,
                )[:5],
                "narrative": narrative,
                "details": details,
                "analyzed_at": time.time(),
            }

        except Exception as e:
            logger.error("attack_chain_analyze_failed", error=str(e))
            return {"success": False, "error": str(e)}

    # ═══════════════════════════════════════════════════════
    #  Narrative
    # ═══════════════════════════════════════════════════════

    @classmethod
    def _build_narrative(
        cls,
        signals: List[Dict[str, Any]],
        stage_counts: Dict[str, int],
        signal_type_counts: Dict[str, int],
    ) -> str:
        """بيبني narrative وصفي للـ attack chain."""
        if not signals:
            return "No activity"

        lines = []

        # المدة
        sorted_sigs = sorted(signals, key=lambda x: x.get("timestamp", 0))
        first_ts = sorted_sigs[0].get("timestamp", 0)
        last_ts = sorted_sigs[-1].get("timestamp", 0)

        try:
            first_dt = datetime.fromtimestamp(first_ts, tz=timezone.utc)
            last_dt = datetime.fromtimestamp(last_ts, tz=timezone.utc)
            duration = last_ts - first_ts

            if duration < 60:
                duration_str = f"{int(duration)}s"
            elif duration < 3600:
                duration_str = f"{int(duration / 60)}m"
            else:
                duration_str = f"{round(duration / 3600, 1)}h"

            lines.append(
                f"Activity from {first_dt.strftime('%H:%M')} "
                f"to {last_dt.strftime('%H:%M')} UTC ({duration_str})"
            )
        except (ValueError, OSError):
            pass

        # الـ stages
        if stage_counts:
            stage_summary = ", ".join(
                f"{count}× {stage}"
                for stage, count in sorted(
                    stage_counts.items(),
                    key=lambda x: x[1],
                    reverse=True,
                )
            )
            lines.append(f"Stages observed: {stage_summary}")

        # أهم الـ signals
        if signal_type_counts:
            top_signals = sorted(
                signal_type_counts.items(),
                key=lambda x: x[1],
                reverse=True,
            )[:3]

            signals_str = ", ".join(
                f"{sig} ({count})" for sig, count in top_signals
            )
            lines.append(f"Top signals: {signals_str}")

        return " | ".join(lines)

    # ═══════════════════════════════════════════════════════
    #  Utilities
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def get_chain_summary(
        cls,
        entity_type: str,
        entity_value: str,
    ) -> Dict[str, Any]:
        """بيرجع ملخص سريع للـ chain."""
        client = cls.get_client()
        if not client:
            return {"success": False, "error": "redis_unavailable"}

        try:
            chain_key = cls._chain_key(entity_type, entity_value)
            data = await client.hgetall(chain_key)

            if not data:
                return {
                    "success": True,
                    "has_chain": False,
                    "entity": f"{entity_type}:{entity_value}",
                }

            # جمع stages
            stages = {
                k.replace("stage:", ""): int(v)
                for k, v in data.items()
                if k.startswith("stage:")
            }

            return {
                "success": True,
                "has_chain": True,
                "entity": f"{entity_type}:{entity_value}",
                "total_signals": int(data.get("total_signals", 0)),
                "stages": stages,
                "started_at": data.get("started_at"),
                "last_updated": data.get("last_updated"),
            }

        except Exception as e:
            logger.error("attack_chain_summary_failed", error=str(e))
            return {"success": False, "error": str(e)}

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
                cls._chain_key(entity_type, entity_value),
                cls._signals_key(entity_type, entity_value),
            ]
            await client.delete(*keys)

            logger.info(
                "attack_chain_cleared",
                entity=f"{entity_type}:{entity_value}",
            )

            return {"success": True}

        except Exception as e:
            logger.error("attack_chain_clear_entity_failed", error=str(e))
            return {"success": False, "error": str(e)}

    @classmethod
    async def clear_all(cls) -> None:
        """بيمسح كل بيانات الـ attack chain."""
        client = cls.get_client()
        if not client:
            return

        try:
            cursor = 0
            while True:
                cursor, keys = await client.scan(
                    cursor=cursor,
                    match="ac:*",
                    count=100,
                )
                if keys:
                    await client.delete(*keys)
                if cursor == 0:
                    break

            logger.info("attack_chain_all_cleared")
        except Exception as e:
            logger.error("attack_chain_clear_all_failed", error=str(e))

    @classmethod
    async def close(cls) -> None:
        """بتقفل Redis."""
        if cls._redis_client:
            await cls._redis_client.close()
            cls._redis_client = None


# ─── Standalone functions ─────────────────────────────

async def record_signal(
    entity_type: str,
    entity_value: str,
    signal_type: str,
    **kwargs,
) -> Dict[str, Any]:
    """Shortcut for AttackChain.record_signal."""
    return await AttackChain.record_signal(
        entity_type, entity_value, signal_type, **kwargs,
    )


async def analyze(
    entity_type: str,
    entity_value: str,
    **kwargs,
) -> Dict[str, Any]:
    """Shortcut for AttackChain.analyze."""
    return await AttackChain.analyze(entity_type, entity_value, **kwargs)