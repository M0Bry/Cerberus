"""
User Baseline — Per-user behavior baseline & deviation detection.

بيوفر:
- Per-user behavior baseline (login times, locations, devices, endpoints)
- Incremental baseline building (يتحدث مع كل event)
- Deviation detection (يقارن event الحالي بالـ baseline)
- Anomaly scoring
- Baseline statistics
- Baseline persistence (Redis)
- Time-based patterns (ساعات، أيام)
- Device/location tracking
- Endpoint preferences

الفكرة:
- كل مستخدم عنده نمط سلوكي معين
- نبني baseline من الأحداث الطبيعية
- لو حدث جديد شاذ مقارنة بالـ baseline → deviation عالية
- مناسب لـ:
  * Account Takeover detection
  * Insider threat detection
  * Compromised account detection

الاستخدام:
- account_takeover.py
- session_analyzer.py
- anomaly_detection.py
- defense_service.py
"""

import json
import math
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import redis.asyncio as redis
import structlog

from app.core.config import settings

logger = structlog.get_logger()


class UserBaseline:
    """
    Per-User Behavior Baseline.

    الفكرة:
    - بنجمع أحداث كل مستخدم
    - بنحسب توزيعات: hours, countries, devices, endpoints
    - كل event جديد بنقارنه بالـ baseline
    """

    _redis_client: Optional[redis.Redis] = None

    # ─── Config ────────────────────────────────────────────
    BASELINE_TTL = 86400 * 90    # 90 يوم
    EVENTS_TTL = 86400 * 30      # 30 يوم
    MAX_RECENT_EVENTS = 200

    # ─── Thresholds ────────────────────────────────────────
    MIN_EVENTS_FOR_BASELINE = 10      # أقل عدد events لبناء baseline
    RARE_EVENT_THRESHOLD = 2          # حدث ظهر مرتين أو أقل = نادر

    # ─── Deviation Weights ────────────────────────────────
    WEIGHTS = {
        "new_country": 40,
        "new_device": 45,
        "new_user_agent": 30,
        "new_ip": 20,
        "unusual_hour": 25,
        "unusual_endpoint": 20,
        "unusual_day": 15,
        "rare_country": 30,
        "rare_device": 35,
        "rare_user_agent": 25,
        "rate_spike": 35,
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
                logger.error("user_baseline_redis_init_failed", error=str(e))
                return None
        return cls._redis_client

    @staticmethod
    def _baseline_key(user_id: str) -> str:
        return f"ub:baseline:{user_id}"

    @staticmethod
    def _events_key(user_id: str) -> str:
        return f"ub:events:{user_id}"

    @staticmethod
    def _empty_baseline(user_id: str) -> Dict[str, Any]:
        """بيبني baseline فاضي."""
        return {
            "user_id": user_id,
            "total_events": 0,
            "created_at": time.time(),
            "last_updated": time.time(),

            # Time patterns
            "hour_counts": {},
            "day_counts": {},
            "weekend_count": 0,
            "weekday_count": 0,

            # Location
            "country_counts": {},
            "ip_counts": {},

            # Device
            "device_counts": {},
            "user_agent_counts": {},

            # Endpoints
            "endpoint_counts": {},
            "method_counts": {},

            # Session stats
            "session_durations": [],
            "actions_per_session": [],

            # Login specific
            "login_success_count": 0,
            "login_failure_count": 0,
        }

    # ═══════════════════════════════════════════════════════
    #  Recording / Updating
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def update_baseline(
        cls,
        user_id: str,
        event: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        بيسجل event ويحدّث baseline المستخدم.
        """
        client = cls.get_client()
        if not client:
            return {"success": False, "error": "redis_unavailable"}

        try:
            if not user_id:
                return {"success": False, "error": "missing_user_id"}

            now = time.time()

            # ─── استرجع baseline الحالي ───
            baseline_key = cls._baseline_key(user_id)
            raw = await client.get(baseline_key)

            if raw:
                baseline = json.loads(raw)
            else:
                baseline = cls._empty_baseline(user_id)

            # ─── استخرج القيم ───
            ts = event.get("timestamp") or now

            # Time
            try:
                dt = datetime.fromtimestamp(ts, tz=timezone.utc)
                hour = dt.hour
                day = dt.weekday()
                is_weekend = day >= 5
            except (ValueError, OSError):
                hour = -1
                day = -1
                is_weekend = False

            hour_key = str(hour)
            day_key = str(day)

            baseline["hour_counts"][hour_key] = baseline["hour_counts"].get(hour_key, 0) + 1
            baseline["day_counts"][day_key] = baseline["day_counts"].get(day_key, 0) + 1

            if is_weekend:
                baseline["weekend_count"] += 1
            else:
                baseline["weekday_count"] += 1

            # Location
            country = event.get("country")
            if country:
                baseline["country_counts"][country] = (
                    baseline["country_counts"].get(country, 0) + 1
                )

            ip = event.get("ip")
            if ip:
                baseline["ip_counts"][ip] = baseline["ip_counts"].get(ip, 0) + 1

            # Device
            device = event.get("device_fingerprint")
            if device:
                baseline["device_counts"][device] = (
                    baseline["device_counts"].get(device, 0) + 1
                )

            ua = event.get("user_agent")
            if ua:
                ua_short = ua[:200]
                baseline["user_agent_counts"][ua_short] = (
                    baseline["user_agent_counts"].get(ua_short, 0) + 1
                )

            # Endpoint
            endpoint = event.get("endpoint")
            if endpoint:
                ep_short = endpoint[:200]
                baseline["endpoint_counts"][ep_short] = (
                    baseline["endpoint_counts"].get(ep_short, 0) + 1
                )

            method = event.get("method")
            if method:
                baseline["method_counts"][method] = (
                    baseline["method_counts"].get(method, 0) + 1
                )

            # Session duration
            session_dur = event.get("session_duration_seconds")
            if session_dur is not None and session_dur >= 0:
                durations = baseline.get("session_durations", [])
                durations.append(float(session_dur))
                baseline["session_durations"] = durations[-50:]

            # Actions per session
            actions = event.get("actions_in_session")
            if actions is not None and actions >= 0:
                arr = baseline.get("actions_per_session", [])
                arr.append(float(actions))
                baseline["actions_per_session"] = arr[-50:]

            # Login success/failure
            status = event.get("status_code", 200)
            if status == 200 and event.get("endpoint", "").endswith(("login", "auth")):
                baseline["login_success_count"] += 1
            elif status in (401, 403):
                baseline["login_failure_count"] += 1

            # ─── Update totals ───
            baseline["total_events"] += 1
            baseline["last_updated"] = now

            # ─── Save ───
            await client.set(
                baseline_key,
                json.dumps(baseline),
                ex=cls.BASELINE_TTL,
            )

            # ─── Save recent event ───
            events_key = cls._events_key(user_id)
            recent_event = {
                "timestamp": ts,
                "ip": ip or "",
                "country": country or "",
                "device": device or "",
                "user_agent": (ua or "")[:200],
                "endpoint": (endpoint or "")[:200],
                "method": method or "",
                "status_code": status,
            }
            await client.lpush(events_key, json.dumps(recent_event))
            await client.ltrim(events_key, 0, cls.MAX_RECENT_EVENTS - 1)
            await client.expire(events_key, cls.EVENTS_TTL)

            return {
                "success": True,
                "user_id": user_id,
                "total_events": baseline["total_events"],
            }

        except Exception as e:
            logger.error("user_baseline_update_failed", error=str(e))
            return {"success": False, "error": str(e)}

    @classmethod
    async def get_baseline(
        cls,
        user_id: str,
    ) -> Optional[Dict[str, Any]]:
        """بيرجع baseline المستخدم."""
        client = cls.get_client()
        if not client:
            return None

        try:
            raw = await client.get(cls._baseline_key(user_id))
            if not raw:
                return None
            return json.loads(raw)
        except Exception as e:
            logger.error("user_baseline_get_failed", error=str(e))
            return None

    @classmethod
    async def has_baseline(
        cls,
        user_id: str,
        min_events: Optional[int] = None,
    ) -> bool:
        """بيتحقق لو المستخدم عنده baseline كافي."""
        baseline = await cls.get_baseline(user_id)
        if not baseline:
            return False

        min_events = min_events or cls.MIN_EVENTS_FOR_BASELINE
        return baseline.get("total_events", 0) >= min_events

    # ═══════════════════════════════════════════════════════
    #  Deviation Detection
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def _is_rare(
        counter: Dict[str, int],
        value: str,
        threshold: int = RARE_EVENT_THRESHOLD,
    ) -> bool:
        """بيتحقق لو القيمة نادرة (ظهرت أقل من threshold)."""
        count = counter.get(value, 0)
        return count <= threshold

    @staticmethod
    def _is_new(
        counter: Dict[str, int],
        value: str,
    ) -> bool:
        """بيتحقق لو القيمة جديدة تماماً."""
        return value not in counter

    @staticmethod
    def _hour_deviation(
        hour_counts: Dict[str, int],
        hour: int,
        total_events: int,
    ) -> Tuple[bool, float]:
        """
        بيحسب deviation في الساعة.

        Returns:
            (is_unusual, severity_score)
        """
        if total_events < 10 or not hour_counts:
            return False, 0.0

        count = hour_counts.get(str(hour), 0)
        ratio = count / total_events

        if ratio < 0.05:
            return True, 0.8
        elif ratio < 0.15:
            return True, 0.4

        return False, 0.0

    @classmethod
    async def analyze_event(
        cls,
        user_id: str,
        event: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        بيحلل event جديد ويقارنه بالـ baseline.
        """
        baseline = await cls.get_baseline(user_id)

        if not baseline or baseline.get("total_events", 0) < cls.MIN_EVENTS_FOR_BASELINE:
            return {
                "success": True,
                "user_id": user_id,
                "is_anomalous": False,
                "deviation_score": 0,
                "level": "no_baseline",
                "signals": [],
                "details": {},
                "has_baseline": False,
            }

        try:
            signals: List[str] = []
            details: Dict[str, Any] = {}
            total_score = 0

            total_events = baseline["total_events"]

            # ─── 1. Country ───
            country = event.get("country")
            if country:
                country_counts = baseline.get("country_counts", {})
                if cls._is_new(country_counts, country):
                    signals.append("new_country")
                    total_score += cls.WEIGHTS["new_country"]
                    details["new_country"] = {"country": country}
                elif cls._is_rare(country_counts, country):
                    signals.append("rare_country")
                    total_score += cls.WEIGHTS["rare_country"]
                    details["rare_country"] = {
                        "country": country,
                        "count": country_counts.get(country, 0),
                    }

            # ─── 2. Device ───
            device = event.get("device_fingerprint")
            if device:
                device_counts = baseline.get("device_counts", {})
                if cls._is_new(device_counts, device):
                    signals.append("new_device")
                    total_score += cls.WEIGHTS["new_device"]
                    details["new_device"] = {
                        "device": device[:30] + "..." if len(device) > 30 else device,
                    }
                elif cls._is_rare(device_counts, device):
                    signals.append("rare_device")
                    total_score += cls.WEIGHTS["rare_device"]
                    details["rare_device"] = {
                        "count": device_counts.get(device, 0),
                    }

            # ─── 3. User Agent ───
            ua = event.get("user_agent")
            if ua:
                ua_short = ua[:200]
                ua_counts = baseline.get("user_agent_counts", {})
                if cls._is_new(ua_counts, ua_short):
                    signals.append("new_user_agent")
                    total_score += cls.WEIGHTS["new_user_agent"]
                    details["new_user_agent"] = {"ua": ua_short[:80] + "..."}
                elif cls._is_rare(ua_counts, ua_short):
                    signals.append("rare_user_agent")
                    total_score += cls.WEIGHTS["rare_user_agent"]
                    details["rare_user_agent"] = {
                        "count": ua_counts.get(ua_short, 0),
                    }

            # ─── 4. IP ───
            ip = event.get("ip")
            if ip:
                ip_counts = baseline.get("ip_counts", {})
                if cls._is_new(ip_counts, ip):
                    signals.append("new_ip")
                    total_score += cls.WEIGHTS["new_ip"]
                    details["new_ip"] = {"ip": ip}

            # ─── 5. Hour ───
            ts = event.get("timestamp") or time.time()
            try:
                dt = datetime.fromtimestamp(ts, tz=timezone.utc)
                hour = dt.hour
                day = dt.weekday()

                hour_counts = baseline.get("hour_counts", {})
                is_unusual, severity = cls._hour_deviation(
                    hour_counts, hour, total_events
                )
                if is_unusual:
                    signals.append("unusual_hour")
                    confidence = cls.WEIGHTS["unusual_hour"] * severity
                    total_score += confidence
                    details["unusual_hour"] = {
                        "hour": hour,
                        "usual_hours": [
                            int(h) for h, _ in sorted(
                                hour_counts.items(),
                                key=lambda x: x[1],
                                reverse=True,
                            )[:3]
                        ],
                        "severity": round(severity, 2),
                    }

                # Day of week
                day_counts = baseline.get("day_counts", {})
                if cls._is_new(day_counts, str(day)) and total_events > 30:
                    signals.append("unusual_day")
                    total_score += cls.WEIGHTS["unusual_day"]
                    details["unusual_day"] = {"day": day}
            except (ValueError, OSError):
                pass

            # ─── 6. Endpoint ───
            endpoint = event.get("endpoint")
            if endpoint:
                ep_short = endpoint[:200]
                ep_counts = baseline.get("endpoint_counts", {})
                if cls._is_new(ep_counts, ep_short) and total_events > 20:
                    signals.append("unusual_endpoint")
                    total_score += cls.WEIGHTS["unusual_endpoint"]
                    details["unusual_endpoint"] = {"endpoint": ep_short[:80]}

            # ─── 7. Rate spike ───
            try:
                events = await cls.get_recent_events(user_id, limit=100)
                if events:
                    now = time.time()
                    last_hour = [
                        e for e in events
                        if now - e.get("timestamp", 0) < 3600
                    ]

                    if total_events > 50:
                        days_span = max(
                            (baseline["last_updated"] - baseline["created_at"]) / 86400,
                            1.0,
                        )
                        avg_per_hour = total_events / (days_span * 24)

                        if avg_per_hour > 0 and len(last_hour) > avg_per_hour * 5:
                            signals.append("rate_spike")
                            total_score += cls.WEIGHTS["rate_spike"]
                            details["rate_spike"] = {
                                "recent_hour": len(last_hour),
                                "avg_per_hour": round(avg_per_hour, 2),
                            }
            except Exception as e:
                logger.debug("rate_spike_check_failed", error=str(e))

            # ─── 8. Deviation score ───
            deviation_score = min(int(math.sqrt(total_score) * 10), 100)

            # ─── 9. Level ───
            level = "clean"
            if deviation_score >= cls.THRESHOLDS["critical"]:
                level = "critical"
            elif deviation_score >= cls.THRESHOLDS["high"]:
                level = "high"
            elif deviation_score >= cls.THRESHOLDS["medium"]:
                level = "medium"
            elif deviation_score >= cls.THRESHOLDS["low"]:
                level = "low"

            # ─── 10. Decision ───
            is_anomalous = deviation_score >= cls.THRESHOLDS["low"]

            if is_anomalous:
                logger.warning(
                    "user_baseline_deviation",
                    user_id=user_id,
                    deviation_score=deviation_score,
                    level=level,
                    signals=signals,
                )

            return {
                "success": True,
                "user_id": user_id,
                "is_anomalous": is_anomalous,
                "deviation_score": deviation_score,
                "level": level,
                "signals": signals,
                "signal_count": len(signals),
                "details": details,
                "has_baseline": True,
                "baseline_events": total_events,
            }

        except Exception as e:
            logger.error("user_baseline_analyze_failed", error=str(e))
            return {"success": False, "error": str(e)}

    # ═══════════════════════════════════════════════════════
    #  Helpers
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def get_recent_events(
        cls,
        user_id: str,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """بيرجع آخر events للمستخدم."""
        client = cls.get_client()
        if not client:
            return []

        try:
            events_key = cls._events_key(user_id)
            raw_events = await client.lrange(events_key, 0, limit - 1)

            events = []
            for raw in raw_events:
                try:
                    events.append(json.loads(raw))
                except json.JSONDecodeError:
                    continue

            return events
        except Exception as e:
            logger.error("user_baseline_events_failed", error=str(e))
            return []

    @classmethod
    async def get_stats(
        cls,
        user_id: str,
    ) -> Dict[str, Any]:
        """بيرجع إحصائيات baseline المستخدم."""
        baseline = await cls.get_baseline(user_id)
        if not baseline:
            return {"has_baseline": False, "user_id": user_id}

        total = max(baseline.get("total_events", 1), 1)

        top_countries = sorted(
            baseline.get("country_counts", {}).items(),
            key=lambda x: x[1],
            reverse=True,
        )[:5]

        top_devices = sorted(
            baseline.get("device_counts", {}).items(),
            key=lambda x: x[1],
            reverse=True,
        )[:5]

        top_hours = sorted(
            baseline.get("hour_counts", {}).items(),
            key=lambda x: int(x[0]) if x[0].lstrip("-").isdigit() else 0,
        )

        durations = baseline.get("session_durations", [])
        actions = baseline.get("actions_per_session", [])

        avg_duration = float(np.mean(durations)) if durations else 0.0
        avg_actions = float(np.mean(actions)) if actions else 0.0

        return {
            "has_baseline": True,
            "user_id": user_id,
            "total_events": total,
            "created_at": baseline.get("created_at"),
            "last_updated": baseline.get("last_updated"),
            "unique_countries": len(baseline.get("country_counts", {})),
            "unique_ips": len(baseline.get("ip_counts", {})),
            "unique_devices": len(baseline.get("device_counts", {})),
            "unique_endpoints": len(baseline.get("endpoint_counts", {})),
            "top_countries": [
                {"country": c, "count": n, "ratio": round(n/total, 3)}
                for c, n in top_countries
            ],
            "top_devices_count": len(top_devices),
            "top_hours": [h for h, _ in top_hours],
            "avg_session_duration_sec": round(avg_duration, 2),
            "avg_actions_per_session": round(avg_actions, 2),
            "login_success": baseline.get("login_success_count", 0),
            "login_failure": baseline.get("login_failure_count", 0),
            "weekend_ratio": round(
                baseline.get("weekend_count", 0) / total, 3
            ),
        }

    @classmethod
    async def reset_baseline(cls, user_id: str) -> Dict[str, Any]:
        """بيمسح baseline المستخدم."""
        client = cls.get_client()
        if not client:
            return {"success": False, "error": "redis_unavailable"}

        try:
            keys = [
                cls._baseline_key(user_id),
                cls._events_key(user_id),
            ]
            await client.delete(*keys)

            logger.info("user_baseline_reset", user_id=user_id)

            return {"success": True, "user_id": user_id}

        except Exception as e:
            logger.error("user_baseline_reset_failed", error=str(e))
            return {"success": False, "error": str(e)}

    @classmethod
    async def clear_all(cls) -> None:
        """بيمسح كل الـ baselines."""
        client = cls.get_client()
        if not client:
            return

        try:
            cursor = 0
            while True:
                cursor, keys = await client.scan(
                    cursor=cursor,
                    match="ub:*",
                    count=100,
                )
                if keys:
                    await client.delete(*keys)
                if cursor == 0:
                    break

            logger.info("user_baseline_all_cleared")
        except Exception as e:
            logger.error("user_baseline_clear_all_failed", error=str(e))

    @classmethod
    async def close(cls) -> None:
        """بتقفل Redis."""
        if cls._redis_client:
            await cls._redis_client.close()
            cls._redis_client = None


# ─── Standalone functions ─────────────────────────────

async def update_baseline(
    user_id: str,
    event: Dict[str, Any],
) -> Dict[str, Any]:
    """Shortcut for UserBaseline.update_baseline."""
    return await UserBaseline.update_baseline(user_id, event)


async def analyze_event(
    user_id: str,
    event: Dict[str, Any],
) -> Dict[str, Any]:
    """Shortcut for UserBaseline.analyze_event."""
    return await UserBaseline.analyze_event(user_id, event)


async def get_baseline(user_id: str) -> Optional[Dict[str, Any]]:
    """Shortcut for UserBaseline.get_baseline."""
    return await UserBaseline.get_baseline(user_id)


async def get_stats(user_id: str) -> Dict[str, Any]:
    """Shortcut for UserBaseline.get_stats."""
    return await UserBaseline.get_stats(user_id)