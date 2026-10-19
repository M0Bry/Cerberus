"""
Pattern Detector — Detects complex attack patterns.

بيوفر:
- Credential Stuffing detection
- Password Spraying detection
- Account Takeover (ATO) detection
- Username Enumeration detection
- Session Hijacking detection
- Sequential ID Scanning detection
- Parameter Fuzzing detection
- Confidence scoring
- Redis-backed

الفكرة:
- نجمع البيانات من AbuseDetector + RequestAnalytics
- نحلل الأنماط
- نرجع score + classification

الاستخدام:
- Tier 2 (Behavioral Analysis)
- Auto-mitigation
- Incident Response
"""

import re
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

import redis.asyncio as redis
import structlog

from app.core.config import settings

logger = structlog.get_logger()


class PatternDetector:
    """
    Pattern Detector for complex attacks.

    الفكرة:
    - كل pattern له إشارات
    - نجمع الإشارات
    - نحسب confidence
    """

    _redis_client: Optional[redis.Redis] = None

    # ─── Config ────────────────────────────────────────────
    CACHE_TTL = 3600  # ساعة
    WINDOW = 300      # 5 دقايق

    # ─── Thresholds ────────────────────────────────────────
    THRESHOLDS = {
        "credential_stuffing": {
            "min_attempts": 5,
            "min_unique_emails": 3,
            "max_success_rate": 0.2,
        },
        "password_spraying": {
            "min_attempts": 10,
            "min_unique_emails": 5,
            "max_attempts_per_email": 2,
        },
        "username_enumeration": {
            "min_attempts": 10,
            "max_success_rate": 0.1,
        },
        "sequential_scanning": {
            "min_sequential_ids": 10,
        },
        "parameter_fuzzing": {
            "min_unique_params": 15,
        },
    }

    # ─── Suspicious Parameters ─────────────────────────────
    FUZZING_INDICATORS = [
        r"fuzz",
        r"test",
        r"debug",
        r"admin",
        r"root",
        r"../../../",
        r"\.\./",
    ]

    # ─── Auth Endpoints ────────────────────────────────────
    AUTH_ENDPOINTS = [
        r"/auth/login",
        r"/auth/register",
        r"/auth/verify",
        r"/auth/reset",
        r"/login",
        r"/register",
        r"/signin",
        r"/signup",
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
                logger.error("pattern_detector_redis_init_failed", error=str(e))
                return None
        return cls._redis_client

    @classmethod
    def _build_key(cls, pattern: str, identifier: str) -> str:
        """بتبني مفتاح Redis."""
        return f"pattern:{pattern}:{identifier}"

    # ─── Recording ─────────────────────────────────────────

    @classmethod
    async def record_auth_attempt(
        cls,
        client_ip: str,
        email: str,
        success: bool,
    ) -> None:
        """
        بيسجل محاولة auth (login/register).

        Args:
            client_ip: IP
            email: الإيميل المستخدم
            success: نجحت ولا لأ
        """
        client = cls.get_client()
        if not client:
            return

        try:
            now = time.time()
            cutoff = now - cls.WINDOW

            # Key للـ IP
            key = cls._build_key("auth", client_ip)

            # خزّن المحاولة
            entry = f"{now}:{email}:{1 if success else 0}"
            await client.lpush(key, entry)
            await client.ltrim(key, 0, 999)
            await client.expire(key, cls.WINDOW * 2)

        except Exception as e:
            logger.error("pattern_detector_record_failed", error=str(e))

    @classmethod
    async def record_id_access(
        cls,
        client_ip: str,
        resource_id: int,
        success: bool,
    ) -> None:
        """
        بيسجل access لـ resource ID.
        """
        client = cls.get_client()
        if not client:
            return

        try:
            now = time.time()
            key = cls._build_key("ids", client_ip)

            entry = f"{now}:{resource_id}:{1 if success else 0}"
            await client.lpush(key, entry)
            await client.ltrim(key, 0, 499)
            await client.expire(key, cls.WINDOW * 2)

        except Exception as e:
            logger.error("pattern_detector_id_record_failed", error=str(e))

    @classmethod
    async def record_parameter(
        cls,
        client_ip: str,
        param_name: str,
    ) -> None:
        """بيسجل parameter جديد."""
        client = cls.get_client()
        if not client:
            return

        try:
            key = cls._build_key("params", client_ip)
            await client.sadd(key, param_name)
            await client.expire(key, cls.WINDOW * 2)
        except Exception as e:
            logger.error("pattern_detector_param_record_failed", error=str(e))

    # ─── Auth Attempt Analysis ────────────────────────────

    @classmethod
    async def _get_auth_attempts(
        cls,
        client_ip: str,
    ) -> List[Dict[str, Any]]:
        """بترجع محاولات auth من Redis."""
        client = cls.get_client()
        if not client:
            return []

        try:
            key = cls._build_key("auth", client_ip)
            entries = await client.lrange(key, 0, -1)

            now = time.time()
            cutoff = now - cls.WINDOW

            attempts = []
            for entry in entries:
                try:
                    parts = entry.split(":", 2)
                    timestamp = float(parts[0])
                    if timestamp < cutoff:
                        continue
                    email = parts[1]
                    success = parts[2] == "1"
                    attempts.append({
                        "timestamp": timestamp,
                        "email": email,
                        "success": success,
                    })
                except (ValueError, IndexError):
                    continue

            return attempts
        except Exception as e:
            logger.error("pattern_detector_get_attempts_failed", error=str(e))
            return []

    # ─── Credential Stuffing ──────────────────────────────

    @classmethod
    async def detect_credential_stuffing(
        cls,
        client_ip: str,
    ) -> Dict[str, Any]:
        """
        بيكشف Credential Stuffing.

        الإشارات:
        - محاولات كتير
        - إيميلات فريدة كتير
        - نسبة نجاح منخفضة
        """
        attempts = await cls._get_auth_attempts(client_ip)

        if not attempts:
            return {"detected": False, "confidence": 0, "details": {}}

        total = len(attempts)
        unique_emails = len(set(a["email"] for a in attempts))
        successful = sum(1 for a in attempts if a["success"])
        success_rate = successful / total if total > 0 else 0

        thresholds = cls.THRESHOLDS["credential_stuffing"]

        # فحص الشروط
        meets_conditions = (
            total >= thresholds["min_attempts"]
            and unique_emails >= thresholds["min_unique_emails"]
            and success_rate <= thresholds["max_success_rate"]
        )

        if not meets_conditions:
            return {
                "detected": False,
                "confidence": 0,
                "details": {
                    "total_attempts": total,
                    "unique_emails": unique_emails,
                    "success_rate": round(success_rate, 3),
                },
            }

        # احسب الـ confidence (0-100)
        confidence = 0
        if total >= 20:
            confidence += 30
        elif total >= 10:
            confidence += 20
        else:
            confidence += 10

        if unique_emails >= 10:
            confidence += 40
        elif unique_emails >= 5:
            confidence += 25
        else:
            confidence += 15

        if success_rate < 0.1:
            confidence += 30
        elif success_rate < 0.2:
            confidence += 20

        confidence = min(confidence, 100)

        logger.warning(
            "credential_stuffing_detected",
            ip=client_ip,
            confidence=confidence,
            attempts=total,
            unique_emails=unique_emails,
        )

        return {
            "detected": True,
            "confidence": confidence,
            "details": {
                "total_attempts": total,
                "unique_emails": unique_emails,
                "success_rate": round(success_rate, 3),
                "successful": successful,
            },
        }

    # ─── Password Spraying ────────────────────────────────

    @classmethod
    async def detect_password_spraying(
        cls,
        client_ip: str,
    ) -> Dict[str, Any]:
        """
        بيكشف Password Spraying.

        الإشارات:
        - محاولات كتير
        - إيميلات فريدة كتير
        - محاولات قليلة لكل إيميل
        """
        attempts = await cls._get_auth_attempts(client_ip)

        if not attempts:
            return {"detected": False, "confidence": 0, "details": {}}

        total = len(attempts)
        unique_emails = len(set(a["email"] for a in attempts))

        # احسب attempts per email
        email_counts: Dict[str, int] = defaultdict(int)
        for a in attempts:
            email_counts[a["email"]] += 1

        max_attempts_per_email = max(email_counts.values()) if email_counts else 0
        avg_attempts_per_email = total / unique_emails if unique_emails > 0 else 0

        thresholds = cls.THRESHOLDS["password_spraying"]

        # فحص الشروط
        meets_conditions = (
            total >= thresholds["min_attempts"]
            and unique_emails >= thresholds["min_unique_emails"]
            and max_attempts_per_email <= thresholds["max_attempts_per_email"]
        )

        if not meets_conditions:
            return {
                "detected": False,
                "confidence": 0,
                "details": {
                    "total_attempts": total,
                    "unique_emails": unique_emails,
                    "max_per_email": max_attempts_per_email,
                },
            }

        # احسب الـ confidence
        confidence = 0
        if total >= 30:
            confidence += 30
        elif total >= 15:
            confidence += 20

        if unique_emails >= 15:
            confidence += 40
        elif unique_emails >= 10:
            confidence += 25

        if max_attempts_per_email <= 1:
            confidence += 30
        elif max_attempts_per_email <= 2:
            confidence += 20

        confidence = min(confidence, 100)

        logger.warning(
            "password_spraying_detected",
            ip=client_ip,
            confidence=confidence,
            attempts=total,
            unique_emails=unique_emails,
        )

        return {
            "detected": True,
            "confidence": confidence,
            "details": {
                "total_attempts": total,
                "unique_emails": unique_emails,
                "max_per_email": max_attempts_per_email,
                "avg_per_email": round(avg_attempts_per_email, 2),
            },
        }

    # ─── Username Enumeration ─────────────────────────────

    @classmethod
    async def detect_username_enumeration(
        cls,
        client_ip: str,
    ) -> Dict[str, Any]:
        """
        بيكشف Username Enumeration.

        الإشارات:
        - محاولات كتير
        - نسبة نجاح منخفضة جداً
        """
        attempts = await cls._get_auth_attempts(client_ip)

        if not attempts:
            return {"detected": False, "confidence": 0, "details": {}}

        total = len(attempts)
        successful = sum(1 for a in attempts if a["success"])
        success_rate = successful / total if total > 0 else 0

        thresholds = cls.THRESHOLDS["username_enumeration"]

        meets_conditions = (
            total >= thresholds["min_attempts"]
            and success_rate <= thresholds["max_success_rate"]
        )

        if not meets_conditions:
            return {
                "detected": False,
                "confidence": 0,
                "details": {
                    "total_attempts": total,
                    "success_rate": round(success_rate, 3),
                },
            }

        confidence = min(30 + (total * 2) + int((1 - success_rate) * 30), 100)

        logger.warning(
            "username_enumeration_detected",
            ip=client_ip,
            confidence=confidence,
            attempts=total,
        )

        return {
            "detected": True,
            "confidence": confidence,
            "details": {
                "total_attempts": total,
                "success_rate": round(success_rate, 3),
            },
        }

    # ─── Sequential ID Scanning ───────────────────────────

    @classmethod
    async def detect_sequential_scanning(
        cls,
        client_ip: str,
    ) -> Dict[str, Any]:
        """
        بيكشف مسح IDs متسلسلة (1, 2, 3, ...).

        الإشارات:
        - IDs متتالية
        - عدد كبير
        """
        client = cls.get_client()
        if not client:
            return {"detected": False, "confidence": 0, "details": {}}

        try:
            key = cls._build_key("ids", client_ip)
            entries = await client.lrange(key, 0, -1)

            now = time.time()
            cutoff = now - cls.WINDOW

            ids: List[int] = []
            for entry in entries:
                try:
                    parts = entry.split(":", 2)
                    timestamp = float(parts[0])
                    if timestamp < cutoff:
                        continue
                    resource_id = int(parts[1])
                    ids.append(resource_id)
                except (ValueError, IndexError):
                    continue

            if len(ids) < cls.THRESHOLDS["sequential_scanning"]["min_sequential_ids"]:
                return {
                    "detected": False,
                    "confidence": 0,
                    "details": {"total_ids": len(ids)},
                }

            # رتب الـ IDs
            ids_sorted = sorted(set(ids))

            # احسب أطول تسلسل متتالي
            max_sequential = 1
            current_sequential = 1

            for i in range(1, len(ids_sorted)):
                if ids_sorted[i] == ids_sorted[i-1] + 1:
                    current_sequential += 1
                    max_sequential = max(max_sequential, current_sequential)
                else:
                    current_sequential = 1

            # القرار
            if max_sequential < 5:
                return {
                    "detected": False,
                    "confidence": 0,
                    "details": {
                        "total_ids": len(ids),
                        "max_sequential": max_sequential,
                    },
                }

            confidence = min(40 + (max_sequential * 5), 100)

            logger.warning(
                "sequential_scanning_detected",
                ip=client_ip,
                confidence=confidence,
                max_sequential=max_sequential,
            )

            return {
                "detected": True,
                "confidence": confidence,
                "details": {
                    "total_ids": len(ids),
                    "max_sequential": max_sequential,
                    "sample_ids": ids_sorted[:10],
                },
            }

        except Exception as e:
            logger.error("pattern_detector_sequential_failed", error=str(e))
            return {"detected": False, "confidence": 0, "details": {}}

    # ─── Parameter Fuzzing ────────────────────────────────

    @classmethod
    async def detect_parameter_fuzzing(
        cls,
        client_ip: str,
    ) -> Dict[str, Any]:
        """
        بيكشف Parameter Fuzzing.

        الإشارات:
        - parameters كتير
        - parameters مشبوهة
        """
        client = cls.get_client()
        if not client:
            return {"detected": False, "confidence": 0, "details": {}}

        try:
            key = cls._build_key("params", client_ip)
            params = await client.smembers(key)

            if len(params) < cls.THRESHOLDS["parameter_fuzzing"]["min_unique_params"]:
                return {
                    "detected": False,
                    "confidence": 0,
                    "details": {"total_params": len(params)},
                }

            # فحص الأنماط المشبوهة
            suspicious_params = []
            for param in params:
                for pattern in cls.FUZZING_INDICATORS:
                    if re.search(pattern, param, re.IGNORECASE):
                        suspicious_params.append(param)
                        break

            total_params = len(params)
            suspicious_count = len(suspicious_params)

            if suspicious_count < 3:
                return {
                    "detected": False,
                    "confidence": 0,
                    "details": {
                        "total_params": total_params,
                        "suspicious_params": suspicious_count,
                    },
                }

            confidence = min(
                30 + (total_params * 2) + (suspicious_count * 5),
                100,
            )

            logger.warning(
                "parameter_fuzzing_detected",
                ip=client_ip,
                confidence=confidence,
                total_params=total_params,
                suspicious=suspicious_count,
            )

            return {
                "detected": True,
                "confidence": confidence,
                "details": {
                    "total_params": total_params,
                    "suspicious_params": suspicious_count,
                    "samples": suspicious_params[:5],
                },
            }

        except Exception as e:
            logger.error("pattern_detector_fuzzing_failed", error=str(e))
            return {"detected": False, "confidence": 0, "details": {}}

    # ─── Main Detection ────────────────────────────────────

    @classmethod
    async def detect_all(
        cls,
        client_ip: str,
    ) -> Dict[str, Any]:
        """
        بيكشف كل الأنماط مرة واحدة.

        Returns:
            dict فيه:
            - patterns: dict بكل pattern ونتيجته
            - detected_patterns: list بالأنماط المكتشفة
            - max_confidence: أعلى confidence
            - overall_score: 0-100
            - is_threat: bool
        """
        # 1. شغل كل الـ detectors
        results = {
            "credential_stuffing": await cls.detect_credential_stuffing(client_ip),
            "password_spraying": await cls.detect_password_spraying(client_ip),
            "username_enumeration": await cls.detect_username_enumeration(client_ip),
            "sequential_scanning": await cls.detect_sequential_scanning(client_ip),
            "parameter_fuzzing": await cls.detect_parameter_fuzzing(client_ip),
        }

        # 2. اجمع النتايج
        detected_patterns = []
        max_confidence = 0

        for pattern_name, result in results.items():
            if result["detected"]:
                detected_patterns.append(pattern_name)
                max_confidence = max(max_confidence, result["confidence"])

        # 3. احسب الـ overall score
        # بنجمع الـ confidences مع مراعاة إن كتر الأنماط = خطورة أعلى
        total_confidence = sum(
            r["confidence"] for r in results.values() if r["detected"]
        )
        pattern_count = len(detected_patterns)

        if pattern_count == 0:
            overall_score = 0
        else:
            # avg + bonus for multiple patterns
            avg_confidence = total_confidence / pattern_count
            bonus = min(pattern_count * 5, 20)
            overall_score = min(int(avg_confidence + bonus), 100)

        # 4. القرار
        is_threat = overall_score >= 50

        if is_threat:
            logger.warning(
                "complex_pattern_detected",
                ip=client_ip,
                patterns=detected_patterns,
                overall_score=overall_score,
            )

        return {
            "ip": client_ip,
            "patterns": results,
            "detected_patterns": detected_patterns,
            "pattern_count": pattern_count,
            "max_confidence": max_confidence,
            "overall_score": overall_score,
            "is_threat": is_threat,
        }

    # ─── Utilities ─────────────────────────────────────────

    @classmethod
    async def clear(cls, client_ip: str) -> None:
        """بيمسح كل بيانات IP."""
        client = cls.get_client()
        if not client:
            return

        try:
            keys = [
                cls._build_key("auth", client_ip),
                cls._build_key("ids", client_ip),
                cls._build_key("params", client_ip),
            ]
            await client.delete(*keys)
            logger.info("pattern_detector_cleared", ip=client_ip)
        except Exception as e:
            logger.error("pattern_detector_clear_failed", error=str(e))

    @classmethod
    async def close(cls) -> None:
        """بتقفل Redis."""
        if cls._redis_client:
            await cls._redis_client.close()
            cls._redis_client = None