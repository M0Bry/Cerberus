"""
Session Analyzer — Session behavior analysis & anomaly detection.

بيوفر:
- Session tracking (start, activity, end)
- Session metrics (duration, requests, endpoints, velocity)
- Session anomaly detection (using ML models + heuristics)
- Behavior change detection within sessions
- Session risk scoring
- Integration with user_baseline + ml models
- Redis-backed
- Session fingerprinting

الفكرة:
- كل user session بتتتبع من أول login لحد logout
- بنحلل الأنماط: requests, endpoints, timing, velocity
- لو session behavior شاذ → risk score عالي
- مناسب لـ:
  * Session hijacking detection
  * Account takeover detection
  * Bot session detection
  * Credential stuffing detection

الاستخدام:
- defense_middleware.py
- user_baseline.py
- attack_chain.py
- anomaly_detection.py
"""

import json
import math
import time
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import redis.asyncio as redis
import structlog

from app.core.config import settings

logger = structlog.get_logger()


class SessionAnalyzer:
    """
    Session Analyzer.

    الفكرة:
    - نتتبع كل session من البداية للنهاية
    - نحلل الـ behavior داخل الـ session
    - نحسب risk score
    """

    _redis_client: Optional[redis.Redis] = None

    # ─── Config ────────────────────────────────────────────
    SESSION_TTL = 86400          # 24 ساعة
    MAX_EVENTS_PER_SESSION = 500
    MAX_DURATION_SECONDS = 86400 * 7   # أسبوع

    # ─── Thresholds ────────────────────────────────────────
    HIGH_VELOCITY_RPS = 10       # 10 requests/second
    VERY_HIGH_VELOCITY_RPS = 50
    LONG_SESSION_HOURS = 24      # session > 24 ساعة
    SUSPICIOUS_ENDPOINT_COUNT = 50
    MANY_FAILED_REQUESTS = 10

    # ─── Risk Weights ─────────────────────────────────────
    WEIGHTS = {
        "high_velocity": 25,
        "very_high_velocity": 40,
        "long_session": 15,
        "many_endpoints": 20,
        "many_failures": 30,
        "ip_change": 45,
        "ua_change": 50,
        "device_change": 50,
        "behavior_change": 35,
        "off_hours": 15,
        "unusual_endpoint_pattern": 30,
        "ml_anomaly": 45,
        "empty_session": 20,
        "single_endpoint_spam": 35,
    }

    # ─── Risk Thresholds ──────────────────────────────────
    THRESHOLDS = {
        "low": 30,
        "medium": 50,
        "high": 70,
        "critical": 85,
    }

    # ─── Internal Helpers ─────────────────────────────────

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
                logger.error("session_analyzer_redis_init_failed", error=str(e))
                return None
        return cls._redis_client

    @staticmethod
    def _session_key(session_id: str) -> str:
        return f"session:data:{session_id}"

    @staticmethod
    def _events_key(session_id: str) -> str:
        return f"session:events:{session_id}"

    @staticmethod
    def _user_sessions_key(user_id: str) -> str:
        return f"session:user:{user_id}:active"

    @staticmethod
    def _generate_session_id(
        user_id: str,
        ip: str,
        user_agent: Optional[str] = None,
    ) -> str:
        """بيولّد session_id من بيانات الجلسة."""
        import hashlib
        seed = f"{user_id}:{ip}:{user_agent or ''}:{int(time.time())}"
        return hashlib.sha256(seed.encode()).hexdigest()[:32]

    # ═══════════════════════════════════════════════════════
    #  Recording
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def start_session(
        cls,
        user_id: str,
        ip: str,
        *,
        session_id: Optional[str] = None,
        user_agent: Optional[str] = None,
        device_fingerprint: Optional[str] = None,
        country: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        بيسجل بداية session جديدة.

        Args:
            user_id: ID المستخدم
            ip: IP
            session_id: ID (لو مش موجود، بيتولّد)
            user_agent: UA
            device_fingerprint: بصمة الجهاز
            country: الدولة

        Returns:
            dict فيه session info
        """
        client = cls.get_client()
        if not client:
            return {"success": False, "error": "redis_unavailable"}

        try:
            if not session_id:
                session_id = cls._generate_session_id(user_id, ip, user_agent)

            now = time.time()

            session_data = {
                "session_id": session_id,
                "user_id": user_id,
                "started_at": now,
                "last_activity": now,
                "start_ip": ip,
                "last_ip": ip,
                "start_user_agent": (user_agent or "")[:200],
                "start_device_fingerprint": device_fingerprint or "",
                "start_country": country or "",
                "request_count": 0,
                "failed_count": 0,
                "success_count": 0,
                "ips_seen": [ip],
                "user_agents_seen": [user_agent] if user_agent else [],
                "devices_seen": [device_fingerprint] if device_fingerprint else [],
                "ended_at": None,
                "is_active": True,
                "end_reason": None,
            }

            # 1. خزّن بيانات الـ session
            session_key = cls._session_key(session_id)
            await client.set(
                session_key,
                json.dumps(session_data),
                ex=cls.SESSION_TTL,
            )

            # 2. سجل في active sessions للـ user
            user_key = cls._user_sessions_key(user_id)
            await client.sadd(user_key, session_id)
            await client.expire(user_key, cls.SESSION_TTL)

            logger.info(
                "session_started",
                session_id=session_id,
                user_id=user_id,
                ip=ip,
            )

            return {
                "success": True,
                "session_id": session_id,
                "started_at": now,
            }

        except Exception as e:
            logger.error("session_start_failed", error=str(e))
            return {"success": False, "error": str(e)}

    @classmethod
    async def record_activity(
        cls,
        session_id: str,
        *,
        ip: Optional[str] = None,
        endpoint: Optional[str] = None,
        method: str = "GET",
        status_code: int = 200,
        user_agent: Optional[str] = None,
        device_fingerprint: Optional[str] = None,
        country: Optional[str] = None,
        response_time_ms: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        بيسجل activity في session موجودة.

        Args:
            session_id: ID الـ session
            ip: IP (لو اتغير)
            endpoint: المسار
            method: HTTP method
            status_code: كود الحالة
            user_agent: UA
            device_fingerprint: بصمة
            country: الدولة
            response_time_ms: وقت الاستجابة

        Returns:
            dict فيه success
        """
        client = cls.get_client()
        if not client:
            return {"success": False, "error": "redis_unavailable"}

        try:
            session_key = cls._session_key(session_id)
            raw = await client.get(session_key)

            if not raw:
                return {"success": False, "error": "session_not_found"}

            session_data = json.loads(raw)

            if not session_data.get("is_active", False):
                return {"success": False, "error": "session_ended"}

            now = time.time()

            # 1. حدّث بيانات الـ session
            session_data["last_activity"] = now
            session_data["request_count"] = session_data.get("request_count", 0) + 1

            # Track status
            if 200 <= status_code < 400:
                session_data["success_count"] = session_data.get("success_count", 0) + 1
            elif 400 <= status_code < 600:
                session_data["failed_count"] = session_data.get("failed_count", 0) + 1

            # Track IPs
            if ip:
                session_data["last_ip"] = ip
                ips_seen = session_data.get("ips_seen", [])
                if ip not in ips_seen:
                    ips_seen.append(ip)
                    session_data["ips_seen"] = ips_seen[:20]  # max 20

            # Track UAs
            if user_agent:
                uas = session_data.get("user_agents_seen", [])
                ua_short = user_agent[:200]
                if ua_short not in uas:
                    uas.append(ua_short)
                    session_data["user_agents_seen"] = uas[:10]  # max 10

            # Track devices
            if device_fingerprint:
                devices = session_data.get("devices_seen", [])
                if device_fingerprint not in devices:
                    devices.append(device_fingerprint)
                    session_data["devices_seen"] = devices[:10]

            # Track country
            if country:
                session_data["last_country"] = country

            # Save
            await client.set(
                session_key,
                json.dumps(session_data),
                ex=cls.SESSION_TTL,
            )

            # 2. سجل الـ event في history
            events_key = cls._events_key(session_id)
            event = {
                "timestamp": now,
                "ip": ip or "",
                "endpoint": (endpoint or "")[:200],
                "method": method,
                "status_code": status_code,
                "user_agent": (user_agent or "")[:200],
                "country": country or "",
                "response_time_ms": response_time_ms,
            }
            await client.lpush(events_key, json.dumps(event))
            await client.ltrim(events_key, 0, cls.MAX_EVENTS_PER_SESSION - 1)
            await client.expire(events_key, cls.SESSION_TTL)

            return {
                "success": True,
                "session_id": session_id,
                "request_count": session_data["request_count"],
            }

        except Exception as e:
            logger.error("session_activity_failed", error=str(e))
            return {"success": False, "error": str(e)}

    @classmethod
    async def end_session(
        cls,
        session_id: str,
        reason: str = "logout",
    ) -> Dict[str, Any]:
        """بيسجل نهاية session."""
        client = cls.get_client()
        if not client:
            return {"success": False, "error": "redis_unavailable"}

        try:
            session_key = cls._session_key(session_id)
            raw = await client.get(session_key)

            if not raw:
                return {"success": False, "error": "session_not_found"}

            session_data = json.loads(raw)
            session_data["is_active"] = False
            session_data["ended_at"] = time.time()
            session_data["end_reason"] = reason

            await client.set(
                session_key,
                json.dumps(session_data),
                ex=cls.SESSION_TTL,
            )

            # شيل من active sessions
            user_id = session_data.get("user_id")
            if user_id:
                user_key = cls._user_sessions_key(user_id)
                await client.srem(user_key, session_id)

            logger.info(
                "session_ended",
                session_id=session_id,
                reason=reason,
            )

            return {"success": True, "session_id": session_id}

        except Exception as e:
            logger.error("session_end_failed", error=str(e))
            return {"success": False, "error": str(e)}

    # ═══════════════════════════════════════════════════════
    #  Getters
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def get_session(
        cls,
        session_id: str,
    ) -> Optional[Dict[str, Any]]:
        """بيرجع بيانات session."""
        client = cls.get_client()
        if not client:
            return None

        try:
            session_key = cls._session_key(session_id)
            raw = await client.get(session_key)
            if not raw:
                return None
            return json.loads(raw)
        except Exception as e:
            logger.error("session_get_failed", error=str(e))
            return None

    @classmethod
    async def get_events(
        cls,
        session_id: str,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """بيرجع events الـ session."""
        client = cls.get_client()
        if not client:
            return []

        try:
            events_key = cls._events_key(session_id)
            raw_events = await client.lrange(events_key, 0, limit - 1)

            events = []
            for raw in raw_events:
                try:
                    events.append(json.loads(raw))
                except json.JSONDecodeError:
                    continue

            return events
        except Exception as e:
            logger.error("session_events_get_failed", error=str(e))
            return []

    @classmethod
    async def get_user_active_sessions(
        cls,
        user_id: str,
    ) -> List[str]:
        """بيرجع active sessions لمستخدم."""
        client = cls.get_client()
        if not client:
            return []

        try:
            user_key = cls._user_sessions_key(user_id)
            return list(await client.smembers(user_key))
        except Exception as e:
            logger.error("session_user_active_failed", error=str(e))
            return []

    # ═══════════════════════════════════════════════════════
    #  Detection: Velocity
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def detect_high_velocity(
        events: List[Dict[str, Any]],
        window_seconds: int = 60,
    ) -> Dict[str, Any]:
        """
        بيكشف velocity عالية (requests/second).

        Args:
            events: قائمة events
            window_seconds: نافذة القياس

        Returns:
            dict فيه detected, confidence, details
        """
        if len(events) < 5:
            return {"detected": False, "confidence": 0}

        try:
            # رتب تصاعدي
            sorted_events = sorted(events, key=lambda e: e.get("timestamp", 0))

            now = time.time()
            cutoff = now - window_seconds

            recent = [
                e for e in sorted_events
                if e.get("timestamp", 0) > cutoff
            ]

            if len(recent) < 5:
                return {"detected": False, "confidence": 0}

            # احسب rate
            time_span = (
                recent[-1]["timestamp"] - recent[0]["timestamp"]
            )
            if time_span <= 0:
                time_span = 1.0

            rate = len(recent) / time_span

            if rate >= SessionAnalyzer.VERY_HIGH_VELOCITY_RPS:
                confidence = SessionAnalyzer.WEIGHTS["very_high_velocity"]
                return {
                    "detected": True,
                    "confidence": confidence,
                    "details": {
                        "rate_per_sec": round(rate, 2),
                        "requests": len(recent),
                        "window_seconds": window_seconds,
                        "severity": "very_high",
                    },
                }
            elif rate >= SessionAnalyzer.HIGH_VELOCITY_RPS:
                confidence = SessionAnalyzer.WEIGHTS["high_velocity"]
                return {
                    "detected": True,
                    "confidence": confidence,
                    "details": {
                        "rate_per_sec": round(rate, 2),
                        "requests": len(recent),
                        "window_seconds": window_seconds,
                        "severity": "high",
                    },
                }

            return {"detected": False, "confidence": 0}

        except Exception as e:
            logger.error("session_velocity_failed", error=str(e))
            return {"detected": False, "confidence": 0}

    # ═══════════════════════════════════════════════════════
    #  Detection: Behavior Change
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def detect_behavior_change(
        session_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        بيكشف تغيير في السلوك خلال الـ session.

        - تغيير IP
        - تغيير user_agent
        - تغيير جهاز
        """
        signals = []
        total_confidence = 0

        ips_seen = session_data.get("ips_seen", [])
        uas_seen = session_data.get("user_agents_seen", [])
        devices_seen = session_data.get("devices_seen", [])

        # IP change
        if len(ips_seen) > 1:
            signals.append("ip_change")
            total_confidence += SessionAnalyzer.WEIGHTS["ip_change"]

        # UA change
        if len(uas_seen) > 1:
            signals.append("ua_change")
            total_confidence += SessionAnalyzer.WEIGHTS["ua_change"]

        # Device change
        if len(devices_seen) > 1:
            signals.append("device_change")
            total_confidence += SessionAnalyzer.WEIGHTS["device_change"]

        if signals:
            return {
                "detected": True,
                "confidence": min(total_confidence, 100),
                "details": {
                    "ips_count": len(ips_seen),
                    "uas_count": len(uas_seen),
                    "devices_count": len(devices_seen),
                    "signals": signals,
                },
            }

        return {"detected": False, "confidence": 0}

    # ═══════════════════════════════════════════════════════
    #  Detection: Endpoint Pattern
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def detect_endpoint_pattern_abuse(
        events: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        بيكشف abuse في نمط الـ endpoints.

        - نفس endpoint بيتكرر كتير (spam)
        - endpoints كتير مختلفة (crawling)
        """
        if len(events) < 5:
            return {"detected": False, "confidence": 0}

        try:
            endpoints = [
                e.get("endpoint", "")
                for e in events
                if e.get("endpoint")
            ]

            if not endpoints:
                return {"detected": False, "confidence": 0}

            unique_endpoints = set(endpoints)
            unique_count = len(unique_endpoints)
            total_count = len(endpoints)

            # 1. Same endpoint spam
            counter = Counter(endpoints)
            most_common_endpoint, most_common_count = counter.most_common(1)[0]
            spam_ratio = most_common_count / total_count

            if spam_ratio > 0.7 and most_common_count > 10:
                return {
                    "detected": True,
                    "confidence": SessionAnalyzer.WEIGHTS["single_endpoint_spam"],
                    "details": {
                        "endpoint": most_common_endpoint[:100],
                        "count": most_common_count,
                        "ratio": round(spam_ratio, 3),
                        "reason": "single_endpoint_spam",
                    },
                }

            # 2. Many unique endpoints
            if unique_count >= SessionAnalyzer.SUSPICIOUS_ENDPOINT_COUNT:
                return {
                    "detected": True,
                    "confidence": SessionAnalyzer.WEIGHTS["unusual_endpoint_pattern"],
                    "details": {
                        "unique_endpoints": unique_count,
                        "total_requests": total_count,
                        "reason": "many_unique_endpoints",
                    },
                }

            return {"detected": False, "confidence": 0}

        except Exception as e:
            logger.error("session_endpoint_pattern_failed", error=str(e))
            return {"detected": False, "confidence": 0}

    # ═══════════════════════════════════════════════════════
    #  Detection: Failures
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def detect_high_failures(
        session_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """بيكشف فشل كتير في الـ session."""
        failed = session_data.get("failed_count", 0)
        total = session_data.get("request_count", 0)

        if failed < SessionAnalyzer.MANY_FAILED_REQUESTS:
            return {"detected": False, "confidence": 0}

        failure_ratio = failed / max(total, 1)

        if failure_ratio > 0.5:
            confidence = SessionAnalyzer.WEIGHTS["many_failures"]
            return {
                "detected": True,
                "confidence": confidence,
                "details": {
                    "failed_count": failed,
                    "total": total,
                    "failure_ratio": round(failure_ratio, 3),
                },
            }

        return {"detected": False, "confidence": 0}

    # ═══════════════════════════════════════════════════════
    #  Detection: Long Session
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def detect_long_session(
        session_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """بيكشف session طويلة جداً."""
        started = session_data.get("started_at", 0)
        if not started:
            return {"detected": False, "confidence": 0}

        duration_hours = (time.time() - started) / 3600.0

        if duration_hours >= SessionAnalyzer.LONG_SESSION_HOURS:
            return {
                "detected": True,
                "confidence": SessionAnalyzer.WEIGHTS["long_session"],
                "details": {
                    "duration_hours": round(duration_hours, 2),
                    "threshold_hours": SessionAnalyzer.LONG_SESSION_HOURS,
                },
            }

        return {"detected": False, "confidence": 0}

    # ═══════════════════════════════════════════════════════
    #  Detection: Off Hours
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def detect_off_hours(
        session_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """بيكشف session في ساعات غريبة."""
        started = session_data.get("started_at", 0)
        if not started:
            return {"detected": False, "confidence": 0}

        try:
            from datetime import datetime, timezone
            dt = datetime.fromtimestamp(started, tz=timezone.utc)
            hour = dt.hour

            # Off hours: 2 AM - 5 AM UTC
            if 2 <= hour < 5:
                return {
                    "detected": True,
                    "confidence": SessionAnalyzer.WEIGHTS["off_hours"],
                    "details": {
                        "start_hour_utc": hour,
                    },
                }

            return {"detected": False, "confidence": 0}
        except Exception:
            return {"detected": False, "confidence": 0}

    # ═══════════════════════════════════════════════════════
    #  Main Analysis
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def analyze_session(
        cls,
        session_id: str,
    ) -> Dict[str, Any]:
        """
        تحليل شامل للـ session.

        Returns:
            dict فيه:
            - is_suspicious: bool
            - risk_score: 0-100
            - level: low/medium/high/critical
            - signals: list
            - details: تفاصيل
        """
        session_data = await cls.get_session(session_id)

        if not session_data:
            return {
                "success": False,
                "error": "session_not_found",
                "session_id": session_id,
            }

        events = await cls.get_events(session_id, limit=200)

        signals: List[str] = []
        details: Dict[str, Any] = {}
        total_score = 0

        # 1. High velocity
        velocity = cls.detect_high_velocity(events)
        if velocity["detected"]:
            signals.append("high_velocity")
            total_score += velocity["confidence"]
            details["high_velocity"] = velocity["details"]

        # 2. Behavior change
        behavior = cls.detect_behavior_change(session_data)
        if behavior["detected"]:
            signals.append("behavior_change")
            total_score += behavior["confidence"]
            details["behavior_change"] = behavior["details"]

        # 3. Endpoint pattern
        endpoint_abuse = cls.detect_endpoint_pattern_abuse(events)
        if endpoint_abuse["detected"]:
            signals.append("endpoint_pattern_abuse")
            total_score += endpoint_abuse["confidence"]
            details["endpoint_pattern"] = endpoint_abuse["details"]

        # 4. High failures
        failures = cls.detect_high_failures(session_data)
        if failures["detected"]:
            signals.append("high_failures")
            total_score += failures["confidence"]
            details["high_failures"] = failures["details"]

        # 5. Long session
        long_session = cls.detect_long_session(session_data)
        if long_session["detected"]:
            signals.append("long_session")
            total_score += long_session["confidence"]
            details["long_session"] = long_session["details"]

        # 6. Off hours
        off_hours = cls.detect_off_hours(session_data)
        if off_hours["detected"]:
            signals.append("off_hours")
            total_score += off_hours["confidence"]
            details["off_hours"] = off_hours["details"]

        # 7. Empty session (no activity despite long duration)
        request_count = session_data.get("request_count", 0)
        duration = time.time() - session_data.get("started_at", time.time())
        if request_count == 0 and duration > 3600:
            signals.append("empty_session")
            total_score += cls.WEIGHTS["empty_session"]
            details["empty_session"] = {
                "duration_hours": round(duration / 3600, 2),
                "request_count": 0,
            }

        # 8. ML anomaly detection (لو متاح)
        try:
            ml_result = await cls._ml_anomaly_check(session_data, events)
            if ml_result.get("detected"):
                signals.append("ml_anomaly")
                total_score += ml_result["confidence"]
                details["ml_anomaly"] = ml_result["details"]
        except Exception as e:
            logger.warning("session_ml_check_failed", error=str(e))

        # 9. Risk score
        risk_score = min(int(math.sqrt(total_score) * 10), 100)

        # 10. Level
        level = "clean"
        if risk_score >= cls.THRESHOLDS["critical"]:
            level = "critical"
        elif risk_score >= cls.THRESHOLDS["high"]:
            level = "high"
        elif risk_score >= cls.THRESHOLDS["medium"]:
            level = "medium"
        elif risk_score >= cls.THRESHOLDS["low"]:
            level = "low"

        # 11. Decision
        is_suspicious = risk_score >= cls.THRESHOLDS["low"]

        if is_suspicious:
            logger.warning(
                "session_suspicious",
                session_id=session_id,
                user_id=session_data.get("user_id"),
                risk_score=risk_score,
                level=level,
                signals=signals,
            )

        # 12. Session summary
        duration_seconds = (
            session_data.get("ended_at") or time.time()
        ) - session_data.get("started_at", time.time())

        return {
            "success": True,
            "session_id": session_id,
            "user_id": session_data.get("user_id"),
            "is_suspicious": is_suspicious,
            "risk_score": risk_score,
            "level": level,
            "signals": signals,
            "signal_count": len(signals),
            "details": details,
            "summary": {
                "request_count": request_count,
                "failed_count": session_data.get("failed_count", 0),
                "success_count": session_data.get("success_count", 0),
                "duration_seconds": int(duration_seconds),
                "duration_minutes": round(duration_seconds / 60, 2),
                "ips_count": len(session_data.get("ips_seen", [])),
                "events_count": len(events),
                "is_active": session_data.get("is_active", False),
            },
        }

    # ═══════════════════════════════════════════════════════
    #  ML Integration
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def _ml_anomaly_check(
        cls,
        session_data: Dict[str, Any],
        events: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        بيعمل ML-based anomaly check (لو الموديلات متاحة).

        Returns:
            dict فيه detected, confidence, details
        """
        try:
            # جهّز features من session data + events
            features = cls._extract_features(session_data, events)

            if features is None or len(features) == 0:
                return {"detected": False, "confidence": 0}

            # جرب SVM
            try:
                from app.core.one_class_svm import OneClassSVMDetector
                if OneClassSVMDetector.is_trained():
                    svm_result = OneClassSVMDetector.predict(
                        np.array([features])
                    )
                    if svm_result.get("success") and svm_result.get("is_anomaly"):
                        score = svm_result.get("anomaly_score", 0.0)
                        # لو anomaly_score موجب → anomaly
                        if score > 0:
                            return {
                                "detected": True,
                                "confidence": cls.WEIGHTS["ml_anomaly"],
                                "details": {
                                    "detector": "svm",
                                    "anomaly_score": round(score, 4),
                                },
                            }
            except Exception as e:
                logger.debug("session_svm_check_skipped", error=str(e))

            return {"detected": False, "confidence": 0}

        except Exception as e:
            logger.warning("session_ml_anomaly_failed", error=str(e))
            return {"detected": False, "confidence": 0}

    @staticmethod
    def _extract_features(
        session_data: Dict[str, Any],
        events: List[Dict[str, Any]],
    ) -> Optional[List[float]]:
        """
        بيستخرج features من session للـ ML.

        Returns:
            list of floats (10 features)
        """
        try:
            request_count = session_data.get("request_count", 0)
            failed_count = session_data.get("failed_count", 0)
            ips_count = len(session_data.get("ips_seen", []))
            uas_count = len(session_data.get("user_agents_seen", []))
            devices_count = len(session_data.get("devices_seen", []))

            duration = time.time() - session_data.get("started_at", time.time())
            duration_min = max(duration / 60, 0.01)

            # velocity
            velocity = request_count / duration_min

            # unique endpoints
            endpoints = set(
                e.get("endpoint", "") for e in events
                if e.get("endpoint")
            )
            unique_endpoints = len(endpoints)

            # failure ratio
            failure_ratio = failed_count / max(request_count, 1)

            # avg response time
            response_times = [
                e.get("response_time_ms", 0)
                for e in events
                if e.get("response_time_ms")
            ]
            avg_response = (
                float(np.mean(response_times))
                if response_times else 0.0
            )

            features = [
                float(request_count),
                float(failed_count),
                float(ips_count),
                float(uas_count),
                float(devices_count),
                float(velocity),
                float(unique_endpoints),
                float(failure_ratio),
                float(avg_response),
                float(duration_min),
            ]

            # عالج NaN/Inf
            features = [
                f if np.isfinite(f) else 0.0
                for f in features
            ]

            return features

        except Exception as e:
            logger.debug("session_features_extract_failed", error=str(e))
            return None

    # ═══════════════════════════════════════════════════════
    #  Utilities
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def clear_session(cls, session_id: str) -> None:
        """بيمسح بيانات session."""
        client = cls.get_client()
        if not client:
            return

        try:
            session_data = await cls.get_session(session_id)

            keys = [
                cls._session_key(session_id),
                cls._events_key(session_id),
            ]
            await client.delete(*keys)

            # شيل من active sessions
            if session_data:
                user_id = session_data.get("user_id")
                if user_id:
                    user_key = cls._user_sessions_key(user_id)
                    await client.srem(user_key, session_id)

            logger.info("session_cleared", session_id=session_id)
        except Exception as e:
            logger.error("session_clear_failed", error=str(e))

    @classmethod
    async def clear_all(cls) -> None:
        """بيمسح كل الـ sessions."""
        client = cls.get_client()
        if not client:
            return

        try:
            cursor = 0
            while True:
                cursor, keys = await client.scan(
                    cursor=cursor,
                    match="session:*",
                    count=100,
                )
                if keys:
                    await client.delete(*keys)
                if cursor == 0:
                    break

            logger.info("session_all_cleared")
        except Exception as e:
            logger.error("session_clear_all_failed", error=str(e))

    @classmethod
    async def close(cls) -> None:
        """بتقفل Redis."""
        if cls._redis_client:
            await cls._redis_client.close()
            cls._redis_client = None


# ─── Standalone functions ─────────────────────────────

async def start_session(
    user_id: str,
    ip: str,
    **kwargs,
) -> Dict[str, Any]:
    """Shortcut for SessionAnalyzer.start_session."""
    return await SessionAnalyzer.start_session(user_id, ip, **kwargs)


async def record_activity(
    session_id: str,
    **kwargs,
) -> Dict[str, Any]:
    """Shortcut for SessionAnalyzer.record_activity."""
    return await SessionAnalyzer.record_activity(session_id, **kwargs)


async def end_session(
    session_id: str,
    reason: str = "logout",
) -> Dict[str, Any]:
    """Shortcut for SessionAnalyzer.end_session."""
    return await SessionAnalyzer.end_session(session_id, reason)


async def analyze_session(session_id: str) -> Dict[str, Any]:
    """Shortcut for SessionAnalyzer.analyze_session."""
    return await SessionAnalyzer.analyze_session(session_id)