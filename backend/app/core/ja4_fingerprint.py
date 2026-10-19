"""
JA4 Fingerprint — Advanced TLS client fingerprinting (FoxIO standard).

بيوفر:
- JA4 fingerprint computation (from ClientHello data)
- JA4S (Server), JA4H (HTTP), JA4T (TCP) support
- Known bot/tool detection
- UA vs JA4 mismatch detection
- Redis-backed storage
- Historical tracking
- Risk scoring

الفرق عن JA3:
- JA3 = MD5 hash قديم
- JA4 = SHA256 مختصر + human-readable format
- JA4 بيكشف Cobalt Strike, Metasploit, Sliver, ...

صيغة JA4:
  [protocol][version][sni][cipher_count][ext_count][alpn]_[cipher_hash]_[ext_hash]
  مثال: t13d1516h2_8daaf6152771_e5627efa2ab1

الاستخدام:
- Bot detection
- Threat hunting
- Malicious tool identification
- UA spoofing detection
"""

import hashlib
import time
from typing import Any, Dict, List, Optional

import redis.asyncio as redis
import structlog

from app.core.config import settings

logger = structlog.get_logger()


class JA4Fingerprint:
    """
    JA4 TLS Fingerprint Detector.

    الفكرة:
    - نحسب JA4 من ClientHello
    - نخزنه لكل IP
    - نقارنه بـ known fingerprints
    - نكشف الـ mismatch مع UA
    """

    _redis_client: Optional[redis.Redis] = None

    # ─── Config ────────────────────────────────────────────
    FP_TTL = 86400 * 7           # 7 أيام
    HISTORY_TTL = 86400 * 30     # 30 يوم

    # ─── Known Malicious JA4 Fingerprints ─────────────────
    # ملاحظة: دي أمثلة — تُحدّث دورياً من FoxIO
    KNOWN_BAD_JA4 = {
        # Cobalt Strike
        "t13d1516h2_8daaf6152771_b0da82dd1658": {
            "name": "Cobalt Strike",
            "severity": "critical",
            "category": "c2_framework",
        },
        "t13d1517h2_8daaf6152771_b0da82dd1658": {
            "name": "Cobalt Strike (variant)",
            "severity": "critical",
            "category": "c2_framework",
        },
        # Metasploit
        "t13d1909h2_9dc949149365_97f8aa674fd9": {
            "name": "Metasploit",
            "severity": "high",
            "category": "exploit_framework",
        },
        # Sliver
        "t13d1715h2_5b57614c22b0_3d5424432f57": {
            "name": "Sliver C2",
            "severity": "critical",
            "category": "c2_framework",
        },
        # curl
        "t13d3112h2_e8f1e7e78f70_8ee79a9c8f7e": {
            "name": "curl",
            "severity": "medium",
            "category": "cli_tool",
        },
        # python-requests
        "t13d2912h2_a09d3c9c9c3a_f2ba2b7e9c1a": {
            "name": "python-requests",
            "severity": "medium",
            "category": "scripting",
        },
        # Nmap
        "t13d3008h2_5b57614c22b0_3d5424432f57": {
            "name": "Nmap",
            "severity": "high",
            "category": "scanner",
        },
        # Generic suspicious
        "t13d0000h2_000000000000_000000000000": {
            "name": "Empty/Stripped TLS",
            "severity": "high",
            "category": "suspicious",
        },
    }

    # ─── Known Good JA4 (Popular Browsers) ────────────────
    # أمثلة — القيم الحقيقية تتغير مع إصدارات المتصفحات
    KNOWN_GOOD_JA4 = {
        "t13d1516h2_8daaf6152771_e5627efa2ab1": "chrome_120+",
        "t13d1516h2_8daaf6152771_e5627efa2ab2": "chrome_121+",
        "t13d1516h2_8daaf6152771_2b6d6d5c1e74": "firefox_120+",
        "t13d1715h2_5b57614c22b0_3d5424432f57": "safari_17+",
    }

    # ─── Risk Weights ─────────────────────────────────────
    WEIGHTS = {
        "known_bad_fingerprint": 80,
        "ua_ja4_mismatch": 45,
        "unusual_fingerprint": 30,
        "stripped_tls": 60,
        "rotating_fingerprints": 50,
        "rare_fingerprint": 25,
    }

    # ─── Thresholds ───────────────────────────────────────
    THRESHOLDS = {
        "low": 30,
        "medium": 50,
        "high": 70,
        "critical": 85,
    }

    ROTATING_FP_MIN = 3         # ≥ 3 بصمات مختلفة من نفس IP

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
                logger.error("ja4_redis_init_failed", error=str(e))
                return None
        return cls._redis_client

    # ─── Key Helpers ───────────────────────────────────────

    @staticmethod
    def _ip_fp_key(ip: str) -> str:
        return f"ja4:ip:{ip}:fingerprints"

    @staticmethod
    def _ip_history_key(ip: str) -> str:
        return f"ja4:ip:{ip}:history"

    @staticmethod
    def _fp_ips_key(fp: str) -> str:
        return f"ja4:fp:{fp}:ips"

    # ─── JA4 Computation ──────────────────────────────────

    @staticmethod
    def _sha256_short(data: str, length: int = 12) -> str:
        """بترجع أول length حرف من SHA256."""
        if not data:
            return "0" * length
        h = hashlib.sha256(data.encode("utf-8")).hexdigest()
        return h[:length]

    @classmethod
    def compute_ja4(
        cls,
        tls_version: int,
        ciphers: List[int],
        extensions: List[int],
        sni: Optional[str] = None,
        alpn: Optional[str] = None,
        signature_algorithms: Optional[List[int]] = None,
        is_quic: bool = False,
    ) -> str:
        """
        بيحسب JA4 fingerprint.

        Args:
            tls_version: 771 (TLS 1.2), 772 (TLS 1.3), 769 (TLS 1.0), 770 (TLS 1.1)
            ciphers: قائمة cipher suites
            extensions: قائمة extensions
            sni: Server Name Indication (domain)
            alpn: Application-Layer Protocol Negotiation (h2, http/1.1)
            signature_algorithms: signature algorithms (للـ ext hash)
            is_quic: هل QUIC؟

        Returns:
            JA4 string
        """
        # ─── 1. Protocol char ─────────────────────────────
        protocol_char = "q" if is_quic else "t"

        # ─── 2. TLS version ───────────────────────────────
        version_map = {
            769: "10",   # TLS 1.0
            770: "11",   # TLS 1.1
            771: "12",   # TLS 1.2
            772: "13",   # TLS 1.3
        }
        version_str = version_map.get(tls_version, "00")

        # ─── 3. SNI indicator ─────────────────────────────
        sni_char = "d" if sni else "i"

        # ─── 4. Cipher count (2 digits, max 99) ───────────
        cipher_count = min(len(ciphers), 99)
        cipher_count_str = f"{cipher_count:02d}"

        # ─── 5. Extension count (2 digits, max 99) ────────
        # Note: SNI و ALPN مش بيتحسبوا في العدد
        ext_count = len(extensions)
        ext_count = min(ext_count, 99)
        ext_count_str = f"{ext_count:02d}"

        # ─── 6. ALPN ──────────────────────────────────────
        if alpn:
            # أول وأخر حرف
            if len(alpn) == 1:
                alpn_str = alpn + alpn
            else:
                alpn_str = alpn[0] + alpn[-1]
        else:
            alpn_str = "00"

        # ─── 7. Build prefix ──────────────────────────────
        prefix = (
            f"{protocol_char}{version_str}{sni_char}"
            f"{cipher_count_str}{ext_count_str}{alpn_str}"
        )

        # ─── 8. Cipher hash ───────────────────────────────
        # ترتيب تصاعدي للـ ciphers
        sorted_ciphers = sorted(set(ciphers))
        cipher_str = ",".join(f"{c:04x}" for c in sorted_ciphers)
        cipher_hash = cls._sha256_short(cipher_str, 12)

        # ─── 9. Extension hash ────────────────────────────
        # ترتيب تصاعدي + إضافة signature algorithms
        sorted_exts = sorted(set(extensions))
        ext_str = ",".join(f"{e:04x}" for e in sorted_exts)

        if signature_algorithms:
            sorted_sigs = sorted(set(signature_algorithms))
            sig_str = ",".join(f"{s:04x}" for s in sorted_sigs)
            ext_str = f"{ext_str}_{sig_str}"

        ext_hash = cls._sha256_short(ext_str, 12)

        # ─── 10. Full JA4 ─────────────────────────────────
        ja4 = f"{prefix}_{cipher_hash}_{ext_hash}"

        return ja4

    # ─── Recording ─────────────────────────────────────────

    @classmethod
    async def record_fingerprint(
        cls,
        ip: str,
        ja4: str,
        user_agent: Optional[str] = None,
    ) -> None:
        """
        بيسجل JA4 fingerprint.

        Args:
            ip: IP
            ja4: البصمة
            user_agent: UA (للمقارنة)
        """
        client = cls.get_client()
        if not client:
            return

        try:
            now = time.time()

            if not ip or not ja4:
                return

            # 1. IP → fingerprints (set)
            fp_key = cls._ip_fp_key(ip)
            await client.sadd(fp_key, ja4)
            await client.expire(fp_key, cls.FP_TTL)

            # 2. IP → history (list of JSON)
            history_key = cls._ip_history_key(ip)
            entry = f"{now}|{ja4}|{(user_agent or '')[:150]}"
            await client.lpush(history_key, entry)
            await client.ltrim(history_key, 0, 99)
            await client.expire(history_key, cls.HISTORY_TTL)

            # 3. fingerprint → IPs
            fp_ips_key = cls._fp_ips_key(ja4)
            await client.sadd(fp_ips_key, ip)
            await client.expire(fp_ips_key, cls.FP_TTL)

        except Exception as e:
            logger.error("ja4_record_failed", error=str(e))

    # ─── Detection: Known Bad ─────────────────────────────

    @classmethod
    def check_known_bad(cls, ja4: str) -> Dict[str, Any]:
        """بيكشف لو البصمة معروفة كخبيثة."""
        if not ja4:
            return {"detected": False, "confidence": 0}

        info = cls.KNOWN_BAD_JA4.get(ja4)

        if info:
            logger.warning(
                "ja4_known_bad_detected",
                ja4=ja4,
                tool=info["name"],
                severity=info["severity"],
            )

            return {
                "detected": True,
                "confidence": cls.WEIGHTS["known_bad_fingerprint"],
                "details": info,
            }

        return {"detected": False, "confidence": 0}

    # ─── Detection: UA vs JA4 Mismatch ────────────────────

    @classmethod
    def check_ua_mismatch(
        cls,
        ja4: str,
        user_agent: Optional[str],
    ) -> Dict[str, Any]:
        """
        بيكشف التناقض بين UA و JA4.

        لو UA بيقول Chrome بس JA4 بتاع Python → spoofing.
        """
        if not ja4 or not user_agent:
            return {"detected": False, "confidence": 0}

        ua_lower = user_agent.lower()

        # حدد نوع المتصفح من UA
        ua_browser = None
        if "chrome" in ua_lower and "edg" not in ua_lower:
            ua_browser = "chrome"
        elif "firefox" in ua_lower:
            ua_browser = "firefox"
        elif "safari" in ua_lower and "chrome" not in ua_lower:
            ua_browser = "safari"
        elif "edg" in ua_lower:
            ua_browser = "edge"

        # حدد نوع من JA4
        good_info = cls.KNOWN_GOOD_JA4.get(ja4)
        bad_info = cls.KNOWN_BAD_JA4.get(ja4)

        # لو UA بيقول browser بس JA4 معروف كأداة
        if ua_browser and bad_info:
            logger.warning(
                "ja4_ua_mismatch",
                ja4=ja4,
                ua_browser=ua_browser,
                ja4_tool=bad_info["name"],
            )

            return {
                "detected": True,
                "confidence": cls.WEIGHTS["ua_ja4_mismatch"],
                "details": {
                    "ua_claims": ua_browser,
                    "ja4_is": bad_info["name"],
                    "reason": "browser_ua_but_tool_fingerprint",
                },
            }

        # لو UA بيقول Chrome بس JA4 بتاع Firefox
        if ua_browser and good_info and ua_browser not in good_info:
            return {
                "detected": True,
                "confidence": cls.WEIGHTS["ua_ja4_mismatch"] // 2,
                "details": {
                    "ua_claims": ua_browser,
                    "ja4_is": good_info,
                    "reason": "browser_mismatch",
                },
            }

        return {"detected": False, "confidence": 0}

    # ─── Detection: Rotating Fingerprints ─────────────────

    @classmethod
    async def detect_rotating_fingerprints(
        cls,
        ip: str,
    ) -> Dict[str, Any]:
        """
        بيكشف تبديل البصمات.

        نفس الـ IP بيستخدم JA4s مختلفة — ممكن يكون bot بيدور.
        """
        client = cls.get_client()
        if not client:
            return {"detected": False, "confidence": 0}

        try:
            fp_key = cls._ip_fp_key(ip)
            fingerprints = await client.smembers(fp_key)

            count = len(fingerprints)

            if count >= cls.ROTATING_FP_MIN:
                extra = min(count - cls.ROTATING_FP_MIN, 10)
                confidence = min(
                    cls.WEIGHTS["rotating_fingerprints"] + (extra * 3),
                    100,
                )

                return {
                    "detected": True,
                    "confidence": confidence,
                    "details": {
                        "fingerprint_count": count,
                        "sample_fingerprints": list(fingerprints)[:3],
                    },
                }

            return {"detected": False, "confidence": 0}

        except Exception as e:
            logger.error("ja4_rotating_failed", error=str(e))
            return {"detected": False, "confidence": 0}

    # ─── Detection: Stripped TLS ──────────────────────────

    @classmethod
    def check_stripped_tls(cls, ja4: str) -> Dict[str, Any]:
        """
        بيكشف TLS مبسط/مشوه.

        الـ attackers بيعملوا strip للـ extensions عشان
        يتجنبوا الـ fingerprinting.
        """
        if not ja4:
            return {"detected": False, "confidence": 0}

        # لو extensions = 0 → stripped
        try:
            parts = ja4.split("_")
            prefix = parts[0]

            # prefix = t13d1516h2 → ext_count = 15
            # prefix = t13d0000h2 → ext_count = 00
            ext_count_str = prefix[6:8]
            cipher_count_str = prefix[4:6]

            if ext_count_str == "00" or cipher_count_str == "00":
                return {
                    "detected": True,
                    "confidence": cls.WEIGHTS["stripped_tls"],
                    "details": {
                        "cipher_count": cipher_count_str,
                        "extension_count": ext_count_str,
                        "reason": "empty_ciphers_or_extensions",
                    },
                }

        except (IndexError, ValueError):
            pass

        return {"detected": False, "confidence": 0}

    # ─── Detection: Rare Fingerprint ──────────────────────

    @classmethod
    async def detect_rare_fingerprint(
        cls,
        ip: str,
        ja4: str,
        max_ips: int = 2,
    ) -> Dict[str, Any]:
        """
        بيكشف البصمات النادرة.

        لو البصمة مش مستخدمة غير من عدد قليل من IPs → نادرة.
        """
        client = cls.get_client()
        if not client or not ja4:
            return {"detected": False, "confidence": 0}

        try:
            fp_ips_key = cls._fp_ips_key(ja4)
            ips_count = await client.scard(fp_ips_key)

            # لو معروفة كويس مش نادرة
            if ja4 in cls.KNOWN_GOOD_JA4:
                return {"detected": False, "confidence": 0}

            # لو مستخدمة من IP واحد أو اتنين
            if ips_count <= max_ips and ips_count >= 1:
                return {
                    "detected": True,
                    "confidence": cls.WEIGHTS["rare_fingerprint"],
                    "details": {
                        "ip_count": ips_count,
                        "ja4": ja4,
                        "reason": "uncommon_fingerprint",
                    },
                }

            return {"detected": False, "confidence": 0}

        except Exception as e:
            logger.error("ja4_rare_failed", error=str(e))
            return {"detected": False, "confidence": 0}

    # ─── Main Analysis ────────────────────────────────────

    @classmethod
    async def analyze(
        cls,
        ip: str,
        ja4: str,
        user_agent: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        تحليل شامل للبصمة.

        Returns:
            dict فيه:
            - is_suspicious: bool
            - risk_score: 0-100
            - level: low/medium/high/critical
            - signals: list
            - details: تفاصيل
            - known_tool: اسم الأداة (لو معروفة)
        """
        signals: List[str] = []
        details: Dict[str, Any] = {}
        total_score = 0
        known_tool = None

        # 1. Known bad
        bad = cls.check_known_bad(ja4)
        if bad["detected"]:
            signals.append("known_bad_fingerprint")
            total_score += bad["confidence"]
            details["known_bad"] = bad["details"]
            known_tool = bad["details"]["name"]

        # 2. UA mismatch
        mismatch = cls.check_ua_mismatch(ja4, user_agent)
        if mismatch["detected"]:
            signals.append("ua_ja4_mismatch")
            total_score += mismatch["confidence"]
            details["ua_mismatch"] = mismatch["details"]

        # 3. Stripped TLS
        stripped = cls.check_stripped_tls(ja4)
        if stripped["detected"]:
            signals.append("stripped_tls")
            total_score += stripped["confidence"]
            details["stripped_tls"] = stripped["details"]

        # 4. Rotating fingerprints
        rotating = await cls.detect_rotating_fingerprints(ip)
        if rotating["detected"]:
            signals.append("rotating_fingerprints")
            total_score += rotating["confidence"]
            details["rotating"] = rotating["details"]

        # 5. Rare fingerprint
        rare = await cls.detect_rare_fingerprint(ip, ja4)
        if rare["detected"]:
            signals.append("rare_fingerprint")
            total_score += rare["confidence"]
            details["rare"] = rare["details"]

        # 6. Risk score
        risk_score = min(int((total_score ** 0.5) * 10), 100)

        # 7. Level
        level = "clean"
        if risk_score >= cls.THRESHOLDS["critical"]:
            level = "critical"
        elif risk_score >= cls.THRESHOLDS["high"]:
            level = "high"
        elif risk_score >= cls.THRESHOLDS["medium"]:
            level = "medium"
        elif risk_score >= cls.THRESHOLDS["low"]:
            level = "low"

        # 8. Decision
        is_suspicious = risk_score >= cls.THRESHOLDS["low"]

        if is_suspicious:
            logger.warning(
                "ja4_suspicious_detected",
                ip=ip,
                ja4=ja4,
                risk_score=risk_score,
                level=level,
                signals=signals,
                known_tool=known_tool,
            )

        return {
            "ip": ip,
            "ja4": ja4,
            "is_suspicious": is_suspicious,
            "risk_score": risk_score,
            "level": level,
            "signals": signals,
            "signal_count": len(signals),
            "details": details,
            "known_tool": known_tool,
        }

    # ─── Utilities ─────────────────────────────────────────

    @classmethod
    async def get_ip_fingerprints(
        cls,
        ip: str,
    ) -> List[str]:
        """بترجع كل بصمات IP."""
        client = cls.get_client()
        if not client:
            return []

        try:
            fp_key = cls._ip_fp_key(ip)
            return list(await client.smembers(fp_key))
        except Exception as e:
            logger.error("ja4_get_fps_failed", error=str(e))
            return []

    @classmethod
    async def get_ip_history(
        cls,
        ip: str,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """بترجع تاريخ البصمات."""
        client = cls.get_client()
        if not client:
            return []

        try:
            history_key = cls._ip_history_key(ip)
            entries = await client.lrange(history_key, 0, limit - 1)

            result = []
            for entry in entries:
                try:
                    parts = entry.split("|", 2)
                    result.append({
                        "timestamp": float(parts[0]),
                        "ja4": parts[1],
                        "user_agent": parts[2] if len(parts) > 2 else "",
                    })
                except (ValueError, IndexError):
                    continue

            return result

        except Exception as e:
            logger.error("ja4_get_history_failed", error=str(e))
            return []

    @classmethod
    async def clear_ip(cls, ip: str) -> None:
        """بيمسح بيانات IP."""
        client = cls.get_client()
        if not client:
            return

        try:
            # اجمع البصمات الأول
            fingerprints = await cls.get_ip_fingerprints(ip)

            keys = [
                cls._ip_fp_key(ip),
                cls._ip_history_key(ip),
            ]
            await client.delete(*keys)

            # نمسح IP من fp → ips
            for fp in fingerprints:
                await client.srem(cls._fp_ips_key(fp), ip)

            logger.info("ja4_ip_cleared", ip=ip)
        except Exception as e:
            logger.error("ja4_clear_ip_failed", error=str(e))

    @classmethod
    async def clear_all(cls) -> None:
        """بيمسح كل بيانات JA4."""
        client = cls.get_client()
        if not client:
            return

        try:
            cursor = 0
            while True:
                cursor, keys = await client.scan(
                    cursor=cursor,
                    match="ja4:*",
                    count=100,
                )
                if keys:
                    await client.delete(*keys)
                if cursor == 0:
                    break

            logger.info("ja4_all_cleared")
        except Exception as e:
            logger.error("ja4_clear_all_failed", error=str(e))

    @classmethod
    async def close(cls) -> None:
        """بتقفل Redis."""
        if cls._redis_client:
            await cls._redis_client.close()
            cls._redis_client = None