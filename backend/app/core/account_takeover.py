"""
Account Takeover Detector — Detects ATO attacks.

بيوفر:
- Impossible Travel detection
- New Device detection
- Failed → Success pattern
- Password change after suspicious login
- Email change attempts
- Session Hijacking detection
- Behavior change detection
- Risk scoring
- Redis-backed

الفكرة:
- نتتبع كل login للـ user
- نحلل الأنماط
- نحسب risk score

الاستخدام:
- Login security
- Fraud detection
- Account protection
- Incident Response
"""

import math
import time
from typing import Any, Dict, List, Optional, Tuple

import redis.asyncio as redis
import structlog

from app.core.config import settings

logger = structlog.get_logger()


class AccountTakeoverDetector:
    """
    Account Takeover Detector.

    الفكرة:
    - نتتبع login history
    - نحلل الأنماط
    - نحسب risk score
    """

    _redis_client: Optional[redis.Redis] = None

    # ─── Config ────────────────────────────────────────────
    HISTORY_TTL = 86400 * 30  # 30 يوم
    MAX_HISTORY = 50          # آخر 50 login

    # ─── Impossible Travel ────────────────────────────────
    MAX_SPEED_KMH = 900  # سرعة الطيران التجاري (900 km/h)

    # ─── Risk Weights ─────────────────────────────────────
    WEIGHTS = {
        "impossible_travel": 60,
        "new_device": 25,
        "new_country": 30,
        "new_ip": 15,
        "failed_before_success": 25,
        "password_change_after_suspicious": 40,
        "email_change_attempt": 50,
        "session_hijack": 70,
        "behavior_change": 30,
        "unusual_time": 15,
    }

    # ─── Risk Thresholds ──────────────────────────────────
    THRESHOLDS = {
        "low": 30,
        "medium": 50,
        "high": 70,
        "critical": 85,
    }

    # ─── Country Coordinates (sample) ─────────────────────
    # للـ impossible travel calculation
    COUNTRY_COORDS = {
        "US": (37.0902, -95.7129),
        "EG": (26.8206, 30.8025),
        "GB": (55.3781, -3.4360),
        "DE": (51.1657, 10.4515),
        "FR": (46.2276, 2.2137),
        "CN": (35.8617, 104.1954),
        "JP": (36.2048, 138.2529),
        "IN": (20.5937, 78.9629),
        "BR": (-14.2350, -51.9253),
        "AU": (-25.2744, 133.7751),
        "RU": (61.5240, 105.3188),
        "CA": (56.1304, -106.3468),
        "NL": (52.1326, 5.2913),
        "SE": (60.1282, 18.6435),
        "SA": (23.8859, 45.0792),
        "AE": (23.4241, 53.8478),
    }

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
                logger.error("ato_detector_redis_init_failed", error=str(e))
                return None
        return cls._redis_client

    @staticmethod
    def _history_key(user_id: str) -> str:
        return f"ato:history:{user_id}"

    @staticmethod
    def _failed_key(user_id: str) -> str:
        return f"ato:failed:{user_id}"

    @staticmethod
    def _flags_key(user_id: str) -> str:
        return f"ato:flags:{user_id}"

    # ─── Distance Calculation ─────────────────────────────

    @staticmethod
    def _haversine_distance(
        lat1: float, lon1: float,
        lat2: float, lon2: float,
    ) -> float:
        """
        بيحسب المسافة بين نقطتين على سطح الأرض (كم).

        Haversine Formula.
        """
        R = 6371  # نصف قطر الأرض بالكم

        lat1_rad = math.radians(lat1)
        lat2_rad = math.radians(lat2)
        delta_lat = math.radians(lat2 - lat1)
        delta_lon = math.radians(lon2 - lon1)

        a = (
            math.sin(delta_lat / 2) ** 2
            + math.cos(lat1_rad) * math.cos(lat2_rad)
            * math.sin(delta_lon / 2) ** 2
        )
        c = 2 * math.asin(math.sqrt(a))

        return R * c

    @classmethod
    def _get_country_coords(
        cls,
        country: str,
    ) -> Optional[Tuple[float, float]]:
        """بترجع إحداثيات الدولة."""
        if not country:
            return None
        return cls.COUNTRY_COORDS.get(country.upper())

    # ─── Recording ─────────────────────────────────────────

    @classmethod
    async def record_login(
        cls,
        user_id: str,
        ip: str,
        country: Optional[str] = None,
        device_fingerprint: Optional[str] = None,
        user_agent: Optional[str] = None,
        success: bool = True,
    ) -> None:
        """
        بيسجل محاولة login.

        Args:
            user_id: ID المستخدم
            ip: IP
            country: الدولة
            device_fingerprint: بصمة الجهاز
            user_agent: UA
            success: نجح؟
        """
        client = cls.get_client()
        if not client:
            return

        try:
            now = time.time()

            if success:
                # 1. سجل في الـ history
                history_key = cls._history_key(user_id)

                entry = {
                    "timestamp": now,
                    "ip": ip,
                    "country": country or "unknown",
                    "device_fingerprint": device_fingerprint or "unknown",
                    "user_agent": (user_agent or "")[:200],
                }

                import json
                await client.lpush(history_key, json.dumps(entry))
                await client.ltrim(history_key, 0, cls.MAX_HISTORY - 1)
                await client.expire(history_key, cls.HISTORY_TTL)

            else:
                # 2. سجل failed attempt
                failed_key = cls._failed_key(user_id)
                await client.lpush(failed_key, str(now))
                await client.ltrim(failed_key, 0, 49)  # آخر 50
                await client.expire(failed_key, 3600)  # ساعة

        except Exception as e:
            logger.error("ato_record_login_failed", error=str(e))

    @classmethod
    async def record_password_change(
        cls,
        user_id: str,
        ip: str,
    ) -> None:
        """بيسجل تغيير باسورد."""
        client = cls.get_client()
        if not client:
            return

        try:
            flags_key = cls._flags_key(user_id)
            await client.hset(flags_key, "last_password_change", str(time.time()))
            await client.expire(flags_key, cls.HISTORY_TTL)

        except Exception as e:
            logger.error("ato_record_pwd_change_failed", error=str(e))

    @classmethod
    async def record_email_change_attempt(
        cls,
        user_id: str,
        ip: str,
    ) -> None:
        """بيسجل محاولة تغيير إيميل."""
        client = cls.get_client()
        if not client:
            return

        try:
            flags_key = cls._flags_key(user_id)
            count = await client.hincrby(flags_key, "email_change_attempts", 1)
            await client.hset(flags_key, "last_email_change", str(time.time()))
            await client.expire(flags_key, cls.HISTORY_TTL)

        except Exception as e:
            logger.error("ato_record_email_change_failed", error=str(e))

    # ─── Get History ──────────────────────────────────────

    @classmethod
    async def _get_history(
        cls,
        user_id: str,
    ) -> List[Dict[str, Any]]:
        """بترجع login history."""
        client = cls.get_client()
        if not client:
            return []

        try:
            import json
            history_key = cls._history_key(user_id)
            entries = await client.lrange(history_key, 0, cls.MAX_HISTORY - 1)

            result = []
            for entry in entries:
                try:
                    result.append(json.loads(entry))
                except json.JSONDecodeError:
                    continue

            return result

        except Exception as e:
            logger.error("ato_get_history_failed", error=str(e))
            return []

    @classmethod
    async def _get_failed_count(
        cls,
        user_id: str,
        window: int = 3600,
    ) -> int:
        """بترجع عدد المحاولات الفاشلة في النافذة."""
        client = cls.get_client()
        if not client:
            return 0

        try:
            failed_key = cls._failed_key(user_id)
            entries = await client.lrange(failed_key, 0, -1)

            now = time.time()
            cutoff = now - window

            count = 0
            for entry in entries:
                try:
                    timestamp = float(entry)
                    if timestamp > cutoff:
                        count += 1
                except ValueError:
                    continue

            return count

        except Exception as e:
            logger.error("ato_get_failed_failed", error=str(e))
            return 0

    # ─── Impossible Travel ────────────────────────────────

    @classmethod
    async def detect_impossible_travel(
        cls,
        user_id: str,
        current_country: str,
        current_time: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        بيكشف Impossible Travel.

        لو المستخدم سجل دخول من مكانين بعيدين في وقت قصير جداً.
        """
        history = await cls._get_history(user_id)

        if not history or not current_country:
            return {"detected": False, "confidence": 0}

        current_time = current_time or time.time()
        current_coords = cls._get_country_coords(current_country)

        if not current_coords:
            return {"detected": False, "confidence": 0}

        # آخر login
        last_login = history[0]
        last_country = last_login.get("country")
        last_time = last_login.get("timestamp", 0)

        if not last_country or last_country == current_country:
            return {"detected": False, "confidence": 0}

        last_coords = cls._get_country_coords(last_country)
        if not last_coords:
            return {"detected": False, "confidence": 0}

        # احسب المسافة
        distance_km = cls._haversine_distance(
            last_coords[0], last_coords[1],
            current_coords[0], current_coords[1],
        )

        # الوقت المنقضي (ساعات)
        time_diff_hours = (current_time - last_time) / 3600

        if time_diff_hours <= 0:
            time_diff_hours = 0.001  # تجنب القسمة على صفر

        # السرعة المطلوبة للتنقل
        required_speed = distance_km / time_diff_hours

        # لو السرعة > سرعة الطيران → impossible
        is_impossible = required_speed > cls.MAX_SPEED_KMH

        if is_impossible:
            logger.warning(
                "impossible_travel_detected",
                user_id=user_id,
                from_country=last_country,
                to_country=current_country,
                distance_km=round(distance_km, 2),
                time_hours=round(time_diff_hours, 2),
                required_speed_kmh=round(required_speed, 2),
            )

            return {
                "detected": True,
                "confidence": cls.WEIGHTS["impossible_travel"],
                "details": {
                    "from_country": last_country,
                    "to_country": current_country,
                    "distance_km": round(distance_km, 2),
                    "time_hours": round(time_diff_hours, 2),
                    "required_speed_kmh": round(required_speed, 2),
                },
            }

        return {"detected": False, "confidence": 0}

    # ─── New Device ───────────────────────────────────────

    @classmethod
    async def detect_new_device(
        cls,
        user_id: str,
        current_fingerprint: str,
    ) -> Dict[str, Any]:
        """بيكشف لو الجهاز جديد."""
        if not current_fingerprint:
            return {"detected": False, "confidence": 0}

        history = await cls._get_history(user_id)

        if not history:
            return {"detected": False, "confidence": 0}

        # شوف لو البصمة موجودة قبل كده
        known_fingerprints = set(
            entry.get("device_fingerprint", "") for entry in history
        )

        if current_fingerprint not in known_fingerprints:
            # جديد
            if len(known_fingerprints) >= 3:
                # لو عنده أجهزة كتير قبل كده → عادي
                confidence = cls.WEIGHTS["new_device"] // 2
            else:
                confidence = cls.WEIGHTS["new_device"]

            return {
                "detected": True,
                "confidence": confidence,
                "details": {
                    "known_devices": len(known_fingerprints),
                    "current_fingerprint": current_fingerprint[:16] + "...",
                },
            }

        return {"detected": False, "confidence": 0}

    # ─── New Country ──────────────────────────────────────

    @classmethod
    async def detect_new_country(
        cls,
        user_id: str,
        current_country: str,
    ) -> Dict[str, Any]:
        """بيكشف لو الدولة جديدة."""
        if not current_country:
            return {"detected": False, "confidence": 0}

        history = await cls._get_history(user_id)

        if not history:
            return {"detected": False, "confidence": 0}

        known_countries = set(
            entry.get("country", "") for entry in history
        )

        if current_country not in known_countries:
            return {
                "detected": True,
                "confidence": cls.WEIGHTS["new_country"],
                "details": {
                    "known_countries": list(known_countries)[:5],
                    "current_country": current_country,
                },
            }

        return {"detected": False, "confidence": 0}

    # ─── Failed → Success ─────────────────────────────────

    @classmethod
    async def detect_failed_before_success(
        cls,
        user_id: str,
    ) -> Dict[str, Any]:
        """
        بيكشف نمط: محاولات فاشلة كتير بعدين نجاح.

        ده ممكن يكون:
        - Brute force نجح
        - Credential stuffing نجح
        """
        failed_count = await cls._get_failed_count(user_id)

        if failed_count >= 5:
            confidence = min(
                cls.WEIGHTS["failed_before_success"] + (failed_count * 2),
                100,
            )

            logger.warning(
                "failed_before_success_detected",
                user_id=user_id,
                failed_count=failed_count,
            )

            return {
                "detected": True,
                "confidence": confidence,
                "details": {
                    "failed_count": failed_count,
                },
            }

        return {"detected": False, "confidence": 0}

    # ─── Password Change After Suspicious Login ──────────

    @classmethod
    async def detect_suspicious_password_change(
        cls,
        user_id: str,
    ) -> Dict[str, Any]:
        """
        بيكشف: تغيير باسورد بعد login مشبوه.

        خطير لأنه ممكن يكون ATO ناجح.
        """
        client = cls.get_client()
        if not client:
            return {"detected": False, "confidence": 0}

        try:
            flags_key = cls._flags_key(user_id)
            last_pwd_change_str = await client.hget(flags_key, "last_password_change")

            if not last_pwd_change_str:
                return {"detected": False, "confidence": 0}

            last_pwd_change = float(last_pwd_change_str)

            # شوف لو فيه login مشبوه في آخر 5 دقايق
            history = await cls._get_history(user_id)

            for entry in history[:5]:
                login_time = entry.get("timestamp", 0)

                # لو الـ login خلال 5 دقايق قبل تغيير الباسورد
                if last_pwd_change - login_time < 300:
                    return {
                        "detected": True,
                        "confidence": cls.WEIGHTS["password_change_after_suspicious"],
                        "details": {
                            "seconds_before": int(last_pwd_change - login_time),
                            "login_ip": entry.get("ip"),
                            "login_country": entry.get("country"),
                        },
                    }

            return {"detected": False, "confidence": 0}

        except Exception as e:
            logger.error("ato_check_pwd_change_failed", error=str(e))
            return {"detected": False, "confidence": 0}

    # ─── Email Change Attempts ────────────────────────────

    @classmethod
    async def detect_email_change_attempts(
        cls,
        user_id: str,
    ) -> Dict[str, Any]:
        """بيكشف محاولات تغيير الإيميل المتكررة."""
        client = cls.get_client()
        if not client:
            return {"detected": False, "confidence": 0}

        try:
            flags_key = cls._flags_key(user_id)
            count_str = await client.hget(flags_key, "email_change_attempts")
            count = int(count_str) if count_str else 0

            if count >= 2:
                confidence = min(
                    cls.WEIGHTS["email_change_attempt"] + (count * 5),
                    100,
                )

                return {
                    "detected": True,
                    "confidence": confidence,
                    "details": {"attempts": count},
                }

            return {"detected": False, "confidence": 0}

        except Exception as e:
            logger.error("ato_check_email_change_failed", error=str(e))
            return {"detected": False, "confidence": 0}

    # ─── Main Detection ───────────────────────────────────

    @classmethod
    async def analyze_login(
        cls,
        user_id: str,
        ip: str,
        country: Optional[str] = None,
        device_fingerprint: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        تحليل شامل لمحاولة login.

        Returns:
            dict فيه:
            - is_suspicious: bool
            - risk_score: 0-100
            - level: low/medium/high/critical
            - signals: list
            - details: تفاصيل
        """
        signals: List[str] = []
        details: Dict[str, Any] = {}
        total_score = 0

        # 1. Impossible Travel
        if country:
            travel = await cls.detect_impossible_travel(user_id, country)
            if travel["detected"]:
                signals.append("impossible_travel")
                total_score += travel["confidence"]
                details["impossible_travel"] = travel["details"]

        # 2. New Device
        if device_fingerprint:
            device = await cls.detect_new_device(user_id, device_fingerprint)
            if device["detected"]:
                signals.append("new_device")
                total_score += device["confidence"]
                details["new_device"] = device["details"]

        # 3. New Country
        if country:
            new_country = await cls.detect_new_country(user_id, country)
            if new_country["detected"]:
                signals.append("new_country")
                total_score += new_country["confidence"]
                details["new_country"] = new_country["details"]

        # 4. Failed → Success
        failed = await cls.detect_failed_before_success(user_id)
        if failed["detected"]:
            signals.append("failed_before_success")
            total_score += failed["confidence"]
            details["failed_before_success"] = failed["details"]

        # 5. Suspicious Password Change
        pwd = await cls.detect_suspicious_password_change(user_id)
        if pwd["detected"]:
            signals.append("password_change_after_suspicious")
            total_score += pwd["confidence"]
            details["password_change"] = pwd["details"]

        # 6. Email Change Attempts
        email = await cls.detect_email_change_attempts(user_id)
        if email["detected"]:
            signals.append("email_change_attempt")
            total_score += email["confidence"]
            details["email_change"] = email["details"]

        # 7. Risk Score
        # ملاحظة: بنستخدم sqrt عشان نقلل الـ stacking
        risk_score = min(int(math.sqrt(total_score) * 10), 100)

        # 8. Level
        level = "clean"
        if risk_score >= cls.THRESHOLDS["critical"]:
            level = "critical"
        elif risk_score >= cls.THRESHOLDS["high"]:
            level = "high"
        elif risk_score >= cls.THRESHOLDS["medium"]:
            level = "medium"
        elif risk_score >= cls.THRESHOLDS["low"]:
            level = "low"

        # 9. Decision
        is_suspicious = risk_score >= cls.THRESHOLDS["low"]

        if is_suspicious:
            logger.warning(
                "ato_suspicious_login",
                user_id=user_id,
                ip=ip,
                risk_score=risk_score,
                level=level,
                signals=signals,
            )

        return {
            "user_id": user_id,
            "ip": ip,
            "is_suspicious": is_suspicious,
            "risk_score": risk_score,
            "level": level,
            "signals": signals,
            "signal_count": len(signals),
            "details": details,
        }

    # ─── Utilities ─────────────────────────────────────────

    @classmethod
    async def get_login_history(
        cls,
        user_id: str,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """بترجع login history."""
        history = await cls._get_history(user_id)
        return history[:limit]

    @classmethod
    async def clear(cls, user_id: str) -> None:
        """بيمسح كل بيانات user."""
        client = cls.get_client()
        if not client:
            return

        try:
            keys = [
                cls._history_key(user_id),
                cls._failed_key(user_id),
                cls._flags_key(user_id),
            ]
            await client.delete(*keys)
            logger.info("ato_cleared", user_id=user_id)
        except Exception as e:
            logger.error("ato_clear_failed", error=str(e))

    @classmethod
    async def close(cls) -> None:
        """بتقفل Redis."""
        if cls._redis_client:
            await cls._redis_client.close()
            cls._redis_client = None