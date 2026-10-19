"""
Credential Stuffing Detector — Detects credential stuffing attacks.

بيوفر:
- Horizontal attack detection (IP واحد → يوزرز كتير)
- Vertical attack detection (يوزر واحد → IPs كتير)
- Distributed attack detection
- Password reuse detection (نفس باسورد على حسابات مختلفة)
- High failure ratio detection
- Automated timing detection
- Suspicious user agent detection
- Risk scoring
- Redis-backed

الفكرة:
- نتتبع كل login attempt (username, ip, password_hash, ua)
- نحلل الأنماط عبر الـ IPs والـ usernames
- نحسب risk score

الاستخدام:
- Login security
- Brute force / Stuffing prevention
- Fraud detection
- Incident Response
"""

import hashlib
import math
import statistics
import time
from typing import Any, Dict, List, Optional, Set, Tuple

import redis.asyncio as redis
import structlog

from app.core.config import settings

logger = structlog.get_logger()


class CredentialStuffingDetector:
    """
    Credential Stuffing Detector.

    الفكرة:
    - نتتبع login attempts من كل IP و لكل username
    - نحلل الأنماط (horizontal / vertical / distributed)
    - نحسب risk score
    """

    _redis_client: Optional[redis.Redis] = None

    # ─── Config ────────────────────────────────────────────
    IP_WINDOW_TTL = 3600        # ساعة
    USER_WINDOW_TTL = 3600      # ساعة
    PASSWORD_TTL = 86400 * 7    # أسبوع
    MAX_ATTEMPTS_TRACKED = 200  # لكل IP

    # ─── Thresholds ────────────────────────────────────────
    MANY_USERNAMES_THRESHOLD = 5      # IP واحد جرب ≥ 5 usernames
    MANY_IPS_THRESHOLD = 10           # username واحد جربه ≥ 10 IPs
    HIGH_FAILURE_RATIO = 0.85         # ≥ 85% فشل
    MIN_ATTEMPT_INTERVAL = 0.5        # ثانية (أقل = آلي)
    PASSWORD_REUSE_THRESHOLD = 3      # نفس hash على ≥ 3 حسابات

    # ─── Risk Weights ─────────────────────────────────────
    WEIGHTS = {
        "many_usernames_one_ip": 40,
        "many_ips_one_username": 45,
        "distributed_attack": 55,
        "password_reuse": 50,
        "high_failure_ratio": 25,
        "automated_timing": 35,
        "suspicious_user_agent": 15,
        "known_breach_password": 60,
        "very_high_velocity": 40,
    }

    # ─── Risk Thresholds ──────────────────────────────────
    THRESHOLDS = {
        "low": 30,
        "medium": 50,
        "high": 70,
        "critical": 85,
    }

    # ─── Suspicious User Agents ───────────────────────────
    SUSPICIOUS_UA_FRAGMENTS = [
        "curl", "wget", "python-requests", "python-urllib",
        "go-http-client", "java/", "libwww-perl", "okhttp",
        "scrapy", "httpclient", "axios/", "postmanruntime",
    ]

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
                logger.error("cs_detector_redis_init_failed", error=str(e))
                return None
        return cls._redis_client

    # ─── Key Helpers ───────────────────────────────────────

    @staticmethod
    def _ip_users_key(ip: str) -> str:
        return f"cs:ip:{ip}:users"

    @staticmethod
    def _ip_attempts_key(ip: str) -> str:
        return f"cs:ip:{ip}:attempts"

    @staticmethod
    def _user_ips_key(username: str) -> str:
        return f"cs:user:{username}:ips"

    @staticmethod
    def _user_attempts_key(username: str) -> str:
        return f"cs:user:{username}:attempts"

    @staticmethod
    def _pwd_users_key(pwd_hash: str) -> str:
        return f"cs:pwd:{pwd_hash}:users"

    # ─── Helpers ───────────────────────────────────────────

    @staticmethod
    def hash_password(password: str) -> str:
        """
        بيعمل hash للباسورد.

        ملاحظة: ده hash للتحليل الإحصائي بس.
        الـ authentication الحقيقي لازم يستخدم bcrypt/argon2.
        """
        if not password:
            return ""
        return hashlib.sha256(password.encode("utf-8")).hexdigest()[:32]

    @staticmethod
    def _is_suspicious_ua(user_agent: Optional[str]) -> bool:
        """بيكشف لو الـ user agent مشبوه."""
        if not user_agent:
            return True  # مفيش UA = مشبوه

        ua_lower = user_agent.lower()
        for fragment in CredentialStuffingDetector.SUSPICIOUS_UA_FRAGMENTS:
            if fragment in ua_lower:
                return True

        return False

    # ─── Recording ─────────────────────────────────────────

    @classmethod
    async def record_attempt(
        cls,
        username: str,
        ip: str,
        password: Optional[str] = None,
        user_agent: Optional[str] = None,
        success: bool = False,
    ) -> None:
        """
        بيسجل محاولة login.

        Args:
            username: اسم المستخدم
            ip: IP
            password: الباسورد (بيتحول لـ hash)
            user_agent: UA
            success: نجح؟
        """
        client = cls.get_client()
        if not client:
            return

        try:
            now = time.time()
            username = username.lower().strip() if username else ""

            if not username or not ip:
                return

            # 1. IP → usernames
            ip_users_key = cls._ip_users_key(ip)
            await client.sadd(ip_users_key, username)
            await client.expire(ip_users_key, cls.IP_WINDOW_TTL)

            # 2. IP → attempts (timestamps)
            ip_attempts_key = cls._ip_attempts_key(ip)
            await client.lpush(ip_attempts_key, str(now))
            await client.ltrim(ip_attempts_key, 0, cls.MAX_ATTEMPTS_TRACKED - 1)
            await client.expire(ip_attempts_key, cls.IP_WINDOW_TTL)

            # 3. Username → IPs
            user_ips_key = cls._user_ips_key(username)
            await client.sadd(user_ips_key, ip)
            await client.expire(user_ips_key, cls.USER_WINDOW_TTL)

            # 4. Username → attempts
            user_attempts_key = cls._user_attempts_key(username)
            await client.lpush(user_attempts_key, str(now))
            await client.ltrim(user_attempts_key, 0, cls.MAX_ATTEMPTS_TRACKED - 1)
            await client.expire(user_attempts_key, cls.USER_WINDOW_TTL)

            # 5. Password hash → users
            if password:
                pwd_hash = cls.hash_password(password)
                if pwd_hash:
                    pwd_key = cls._pwd_users_key(pwd_hash)
                    await client.sadd(pwd_key, username)
                    await client.expire(pwd_key, cls.PASSWORD_TTL)

        except Exception as e:
            logger.error("cs_record_attempt_failed", error=str(e))

    # ─── Detection: Horizontal ────────────────────────────

    @classmethod
    async def detect_many_usernames_one_ip(
        cls,
        ip: str,
    ) -> Dict[str, Any]:
        """
        بيكشف الهجوم الأفقي: IP واحد بيجرب يوزرز كتير.

        ده أخطر إشارة في credential stuffing.
        """
        client = cls.get_client()
        if not client:
            return {"detected": False, "confidence": 0}

        try:
            ip_users_key = cls._ip_users_key(ip)
            usernames = await client.smembers(ip_users_key)

            count = len(usernames)

            if count >= cls.MANY_USERNAMES_THRESHOLD:
                # كل ما زاد العدد، كل ما زادت الثقة
                extra = min(count - cls.MANY_USERNAMES_THRESHOLD, 20)
                confidence = min(
                    cls.WEIGHTS["many_usernames_one_ip"] + (extra * 2),
                    100,
                )

                logger.warning(
                    "cs_many_usernames_one_ip",
                    ip=ip,
                    username_count=count,
                )

                return {
                    "detected": True,
                    "confidence": confidence,
                    "details": {
                        "username_count": count,
                        "sample_usernames": list(usernames)[:5],
                    },
                }

            return {"detected": False, "confidence": 0}

        except Exception as e:
            logger.error("cs_detect_many_usernames_failed", error=str(e))
            return {"detected": False, "confidence": 0}

    # ─── Detection: Vertical ──────────────────────────────

    @classmethod
    async def detect_many_ips_one_username(
        cls,
        username: str,
    ) -> Dict[str, Any]:
        """
        بيكشف الهجوم العمودي: username واحد بيجي من IPs كتير.

        ده distributed attack (botnet).
        """
        client = cls.get_client()
        if not client:
            return {"detected": False, "confidence": 0}

        try:
            username = username.lower().strip()
            user_ips_key = cls._user_ips_key(username)
            ips = await client.smembers(user_ips_key)

            count = len(ips)

            if count >= cls.MANY_IPS_THRESHOLD:
                extra = min(count - cls.MANY_IPS_THRESHOLD, 30)
                confidence = min(
                    cls.WEIGHTS["many_ips_one_username"] + (extra * 2),
                    100,
                )

                logger.warning(
                    "cs_many_ips_one_username",
                    username=username,
                    ip_count=count,
                )

                return {
                    "detected": True,
                    "confidence": confidence,
                    "details": {
                        "ip_count": count,
                        "sample_ips": list(ips)[:5],
                    },
                }

            return {"detected": False, "confidence": 0}

        except Exception as e:
            logger.error("cs_detect_many_ips_failed", error=str(e))
            return {"detected": False, "confidence": 0}

    # ─── Detection: Password Reuse ────────────────────────

    @classmethod
    async def detect_password_reuse(
        cls,
        password: str,
    ) -> Dict[str, Any]:
        """
        بيكشف: نفس الباسورد مستخدم على حسابات كتير.

        ده أقوى إشارة على credential stuffing —
        لأن المهاجم بيجرب نفس الليستة.
        """
        client = cls.get_client()
        if not client or not password:
            return {"detected": False, "confidence": 0}

        try:
            pwd_hash = cls.hash_password(password)
            if not pwd_hash:
                return {"detected": False, "confidence": 0}

            pwd_key = cls._pwd_users_key(pwd_hash)
            usernames = await client.smembers(pwd_key)

            count = len(usernames)

            if count >= cls.PASSWORD_REUSE_THRESHOLD:
                extra = min(count - cls.PASSWORD_REUSE_THRESHOLD, 15)
                confidence = min(
                    cls.WEIGHTS["password_reuse"] + (extra * 3),
                    100,
                )

                logger.warning(
                    "cs_password_reuse_detected",
                    username_count=count,
                )

                return {
                    "detected": True,
                    "confidence": confidence,
                    "details": {
                        "username_count": count,
                        "sample_usernames": list(usernames)[:5],
                    },
                }

            return {"detected": False, "confidence": 0}

        except Exception as e:
            logger.error("cs_detect_pwd_reuse_failed", error=str(e))
            return {"detected": False, "confidence": 0}

    # ─── Detection: High Failure Ratio ────────────────────

    @classmethod
    async def detect_high_failure_ratio(
        cls,
        ip: str,
        total_recent: int,
        failed_recent: int,
    ) -> Dict[str, Any]:
        """
        بيكشف نسبة فشل عالية.

        Args:
            ip: IP
            total_recent: إجمالي المحاولات (من مصدر تاني)
            failed_recent: عدد الفشل
        """
        if total_recent < 5:
            return {"detected": False, "confidence": 0}

        ratio = failed_recent / total_recent

        if ratio >= cls.HIGH_FAILURE_RATIO:
            # كل ما زادت النسبة، كل ما زادت الثقة
            extra = (ratio - cls.HIGH_FAILURE_RATIO) * 100
            confidence = min(
                cls.WEIGHTS["high_failure_ratio"] + int(extra),
                100,
            )

            return {
                "detected": True,
                "confidence": confidence,
                "details": {
                    "failure_ratio": round(ratio, 3),
                    "total": total_recent,
                    "failed": failed_recent,
                },
            }

        return {"detected": False, "confidence": 0}

    # ─── Detection: Automated Timing ──────────────────────

    @classmethod
    async def detect_automated_timing(
        cls,
        ip: str,
    ) -> Dict[str, Any]:
        """
        بيكشف التوقيت الآلي.

        البشر مش بيسجلوا دخول كل 0.1 ثانية.
        الـ bots بتعمل كده.
        """
        client = cls.get_client()
        if not client:
            return {"detected": False, "confidence": 0}

        try:
            ip_attempts_key = cls._ip_attempts_key(ip)
            entries = await client.lrange(ip_attempts_key, 0, 49)

            if len(entries) < 5:
                return {"detected": False, "confidence": 0}

            timestamps = []
            for entry in entries:
                try:
                    timestamps.append(float(entry))
                except ValueError:
                    continue

            if len(timestamps) < 5:
                return {"detected": False, "confidence": 0}

            # ترتيب تصاعدي
            timestamps.sort()

            # الفروق بين كل محاولة واللي بعدها
            intervals = [
                timestamps[i + 1] - timestamps[i]
                for i in range(len(timestamps) - 1)
            ]

            if not intervals:
                return {"detected": False, "confidence": 0}

            avg_interval = statistics.mean(intervals)
            std_interval = (
                statistics.stdev(intervals)
                if len(intervals) > 1
                else 0.0
            )

            # الحالة 1: محاولات سريعة جداً
            is_too_fast = avg_interval < cls.MIN_ATTEMPT_INTERVAL

            # الحالة 2: توقيت منتظم جداً (bot)
            # لو الانحراف المعياري أقل من 20% من المتوسط
            is_too_regular = (
                avg_interval > 0
                and (std_interval / avg_interval) < 0.2
            )

            if is_too_fast or is_too_regular:
                confidence = cls.WEIGHTS["automated_timing"]

                if is_too_fast:
                    confidence += 10
                if is_too_regular:
                    confidence += 10

                confidence = min(confidence, 100)

                logger.warning(
                    "cs_automated_timing_detected",
                    ip=ip,
                    avg_interval=round(avg_interval, 3),
                    std_interval=round(std_interval, 3),
                    is_too_fast=is_too_fast,
                    is_too_regular=is_too_regular,
                )

                return {
                    "detected": True,
                    "confidence": confidence,
                    "details": {
                        "avg_interval_sec": round(avg_interval, 3),
                        "std_interval_sec": round(std_interval, 3),
                        "is_too_fast": is_too_fast,
                        "is_too_regular": is_too_regular,
                        "sample_count": len(timestamps),
                    },
                }

            return {"detected": False, "confidence": 0}

        except Exception as e:
            logger.error("cs_detect_timing_failed", error=str(e))
            return {"detected": False, "confidence": 0}

    # ─── Detection: Suspicious UA ─────────────────────────

    @classmethod
    def detect_suspicious_user_agent(
        cls,
        user_agent: Optional[str],
    ) -> Dict[str, Any]:
        """بيكشف user agent مشبوه."""
        if cls._is_suspicious_ua(user_agent):
            return {
                "detected": True,
                "confidence": cls.WEIGHTS["suspicious_user_agent"],
                "details": {
                    "user_agent": (user_agent or "")[:120],
                    "reason": "empty_or_known_bot_ua",
                },
            }

        return {"detected": False, "confidence": 0}

    # ─── Main Detection ───────────────────────────────────

    @classmethod
    async def analyze_attempt(
        cls,
        username: str,
        ip: str,
        password: Optional[str] = None,
        user_agent: Optional[str] = None,
        total_recent: int = 0,
        failed_recent: int = 0,
    ) -> Dict[str, Any]:
        """
        تحليل شامل لمحاولة login من منظور credential stuffing.

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

        # 1. Many usernames / one IP
        horizontal = await cls.detect_many_usernames_one_ip(ip)
        if horizontal["detected"]:
            signals.append("many_usernames_one_ip")
            total_score += horizontal["confidence"]
            details["horizontal"] = horizontal["details"]

        # 2. Many IPs / one username
        vertical = await cls.detect_many_ips_one_username(username)
        if vertical["detected"]:
            signals.append("many_ips_one_username")
            total_score += vertical["confidence"]
            details["vertical"] = vertical["details"]

        # 3. Password reuse
        if password:
            pwd_reuse = await cls.detect_password_reuse(password)
            if pwd_reuse["detected"]:
                signals.append("password_reuse")
                total_score += pwd_reuse["confidence"]
                details["password_reuse"] = pwd_reuse["details"]

        # 4. High failure ratio
        if total_recent > 0:
            failure = await cls.detect_high_failure_ratio(
                ip=ip,
                total_recent=total_recent,
                failed_recent=failed_recent,
            )
            if failure["detected"]:
                signals.append("high_failure_ratio")
                total_score += failure["confidence"]
                details["high_failure_ratio"] = failure["details"]

        # 5. Automated timing
        timing = await cls.detect_automated_timing(ip)
        if timing["detected"]:
            signals.append("automated_timing")
            total_score += timing["confidence"]
            details["automated_timing"] = timing["details"]

        # 6. Suspicious UA
        ua_check = cls.detect_suspicious_user_agent(user_agent)
        if ua_check["detected"]:
            signals.append("suspicious_user_agent")
            total_score += ua_check["confidence"]
            details["suspicious_user_agent"] = ua_check["details"]

        # 7. Combined: distributed attack signal
        # لو الاتنين مع بعض → فيه botnet
        if (
            "many_usernames_one_ip" in signals
            and "many_ips_one_username" in signals
        ):
            signals.append("distributed_attack")
            total_score += cls.WEIGHTS["distributed_attack"]

        # 8. Risk Score (sqrt لتقليل الـ stacking)
        risk_score = min(int(math.sqrt(total_score) * 10), 100)

        # 9. Level
        level = "clean"
        if risk_score >= cls.THRESHOLDS["critical"]:
            level = "critical"
        elif risk_score >= cls.THRESHOLDS["high"]:
            level = "high"
        elif risk_score >= cls.THRESHOLDS["medium"]:
            level = "medium"
        elif risk_score >= cls.THRESHOLDS["low"]:
            level = "low"

        # 10. Decision
        is_suspicious = risk_score >= cls.THRESHOLDS["low"]

        if is_suspicious:
            logger.warning(
                "cs_suspicious_attempt",
                username=username,
                ip=ip,
                risk_score=risk_score,
                level=level,
                signals=signals,
            )

        return {
            "username": username,
            "ip": ip,
            "is_suspicious": is_suspicious,
            "risk_score": risk_score,
            "level": level,
            "signals": signals,
            "signal_count": len(signals),
            "details": details,
        }

    # ─── Stats ─────────────────────────────────────────────

    @classmethod
    async def get_ip_stats(cls, ip: str) -> Dict[str, Any]:
        """بترجع إحصائيات IP."""
        client = cls.get_client()
        if not client:
            return {}

        try:
            ip_users_key = cls._ip_users_key(ip)
            ip_attempts_key = cls._ip_attempts_key(ip)

            usernames = await client.smembers(ip_users_key)
            attempts = await client.llen(ip_attempts_key)

            return {
                "ip": ip,
                "username_count": len(usernames),
                "attempt_count": attempts,
                "sample_usernames": list(usernames)[:10],
            }

        except Exception as e:
            logger.error("cs_get_ip_stats_failed", error=str(e))
            return {}

    @classmethod
    async def get_username_stats(cls, username: str) -> Dict[str, Any]:
        """بترجع إحصائيات username."""
        client = cls.get_client()
        if not client:
            return {}

        try:
            username = username.lower().strip()
            user_ips_key = cls._user_ips_key(username)
            user_attempts_key = cls._user_attempts_key(username)

            ips = await client.smembers(user_ips_key)
            attempts = await client.llen(user_attempts_key)

            return {
                "username": username,
                "ip_count": len(ips),
                "attempt_count": attempts,
                "sample_ips": list(ips)[:10],
            }

        except Exception as e:
            logger.error("cs_get_username_stats_failed", error=str(e))
            return {}

    # ─── Utilities ─────────────────────────────────────────

    @classmethod
    async def clear_ip(cls, ip: str) -> None:
        """بيمسح بيانات IP."""
        client = cls.get_client()
        if not client:
            return

        try:
            keys = [
                cls._ip_users_key(ip),
                cls._ip_attempts_key(ip),
            ]
            await client.delete(*keys)
            logger.info("cs_ip_cleared", ip=ip)
        except Exception as e:
            logger.error("cs_clear_ip_failed", error=str(e))

    @classmethod
    async def clear_username(cls, username: str) -> None:
        """بيمسح بيانات username."""
        client = cls.get_client()
        if not client:
            return

        try:
            username = username.lower().strip()
            keys = [
                cls._user_ips_key(username),
                cls._user_attempts_key(username),
            ]
            await client.delete(*keys)
            logger.info("cs_username_cleared", username=username)
        except Exception as e:
            logger.error("cs_clear_username_failed", error=str(e))

    @classmethod
    async def clear_all(cls) -> None:
        """بيمسح كل بيانات credential stuffing."""
        client = cls.get_client()
        if not client:
            return

        try:
            # نمسح بالـ pattern
            patterns = [
                "cs:ip:*",
                "cs:user:*",
                "cs:pwd:*",
            ]
            for pattern in patterns:
                cursor = 0
                while True:
                    cursor, keys = await client.scan(
                        cursor=cursor,
                        match=pattern,
                        count=100,
                    )
                    if keys:
                        await client.delete(*keys)
                    if cursor == 0:
                        break

            logger.info("cs_all_cleared")
        except Exception as e:
            logger.error("cs_clear_all_failed", error=str(e))

    @classmethod
    async def close(cls) -> None:
        """بتقفل Redis."""
        if cls._redis_client:
            await cls._redis_client.close()
            cls._redis_client = None