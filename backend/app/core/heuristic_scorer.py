"""
Heuristic Scorer — Scores payloads based on multiple threat signals.

بيقيّم خطورة الـ payload بنظام النقاط (0-100).

الإشارات:
- SQL Injection patterns
- XSS patterns
- Command Injection
- Path Traversal
- Advanced threats (XXE, SSRF, ...)
- Encoding techniques
- Entropy
- Length
- Special characters

بيستخدم:
- payload_decoder
- advanced_patterns
- encoding_detector

ملف مستقل — بيستخدم الملفات اللي عملناها.
"""

from typing import Any, Dict, List, Optional

import structlog

from app.core.advanced_patterns import AdvancedPatterns
from app.core.encoding_detector import EncodingDetector
from app.core.payload_decoder import PayloadDecoder

logger = structlog.get_logger()


class HeuristicScorer:
    """
    كلاس لتقييم خطورة الـ payload.

    بيحسب درجة 0-100.
    """

    # ─── Score Weights ─────────────────────────────────────
    WEIGHTS = {
        # Basic attacks (من input_validator الأصلي)
        "sql_injection": 30,
        "xss": 25,
        "command_injection": 30,
        "path_traversal": 20,

        # Advanced attacks (من advanced_patterns)
        "xxe": 25,
        "ssrf": 30,
        "nosql": 25,
        "ldap": 20,
        "ssti": 30,
        "crlf": 15,
        "open_redirect": 10,
        "jwt": 20,
        "prototype_pollution": 20,
        "graphql": 15,
        "deserialization": 35,
        "host_header": 15,

        # Encoding techniques
        "has_homoglyphs": 15,
        "has_zero_width": 10,
        "has_bidi": 15,
        "has_null_bytes": 10,
        "has_control_chars": 8,
        "has_mixed_scripts": 10,
        "high_entropy": 8,
        "multiple_encodings": 12,

        # Behavioral indicators
        "excessive_length": 5,
        "special_char_ratio": 8,
        "repeated_chars": 5,
    }

    # ─── Thresholds ────────────────────────────────────────
    THRESHOLD_LOW = 20       # 0-19 = clean
    THRESHOLD_MEDIUM = 40    # 20-39 = low
    THRESHOLD_HIGH = 60      # 40-59 = medium
    THRESHOLD_CRITICAL = 80  # 60-79 = high, 80+ = critical

    # ─── Main API ──────────────────────────────────────────

    @classmethod
    def score(cls, value: str, field_name: str = "input") -> Dict[str, Any]:
        """
        بيقيّم خطورة الـ payload.

        Args:
            value: الـ payload
            field_name: اسم الحقل (للتسجيل)

        Returns:
            dict فيه:
            - score: 0-100
            - level: clean/low/medium/high/critical
            - signals: dict بكل إشارة ووزنها
            - is_threat: bool
            - should_block: bool
        """
        if not isinstance(value, str) or not value:
            return cls._empty_result()

        # 1. افحص كل الإشارات
        signals = cls._collect_signals(value)

        # 2. احسب الدرجة
        score = cls._calculate_score(signals)

        # 3. حدد المستوى
        level = cls._get_level(score)

        # 4. حدد القرار
        is_threat = score >= cls.THRESHOLD_LOW
        should_block = score >= cls.THRESHOLD_HIGH

        result = {
            "score": score,
            "level": level,
            "signals": signals,
            "is_threat": is_threat,
            "should_block": should_block,
            "field_name": field_name,
            "payload_length": len(value),
        }

        if is_threat:
            logger.warning(
                "threat_scored",
                field=field_name,
                score=score,
                level=level,
                signals=[k for k, v in signals.items() if v],
            )

        return result

    @classmethod
    def _empty_result(cls) -> Dict[str, Any]:
        """نتيجة فاضية."""
        return {
            "score": 0,
            "level": "empty",
            "signals": {},
            "is_threat": False,
            "should_block": False,
            "field_name": "",
            "payload_length": 0,
        }

    # ─── Signal Collection ─────────────────────────────────

    @classmethod
    def _collect_signals(cls, value: str) -> Dict[str, int]:
        """
        بيجمع كل الإشارات من الـ payload.

        Returns:
            dict فيه كل إشارة ووزنها
        """
        signals: Dict[str, int] = {}

        # ─── 1. Basic Attacks (Basic regex) ───
        if cls._detect_sql_injection(value):
            signals["sql_injection"] = cls.WEIGHTS["sql_injection"]

        if cls._detect_xss(value):
            signals["xss"] = cls.WEIGHTS["xss"]

        if cls._detect_command_injection(value):
            signals["command_injection"] = cls.WEIGHTS["command_injection"]

        if cls._detect_path_traversal(value):
            signals["path_traversal"] = cls.WEIGHTS["path_traversal"]

        # ─── 2. Advanced Attacks ───
        advanced = AdvancedPatterns.detect_all(value)
        for name, detected in advanced.items():
            if detected and name in cls.WEIGHTS:
                signals[name] = cls.WEIGHTS[name]

        # ─── 3. Encoding Techniques ───
        encoding = EncodingDetector.detect_all(value)
        if encoding.get("has_homoglyphs"):
            signals["has_homoglyphs"] = cls.WEIGHTS["has_homoglyphs"]
        if encoding.get("has_zero_width"):
            signals["has_zero_width"] = cls.WEIGHTS["has_zero_width"]
        if encoding.get("has_bidi"):
            signals["has_bidi"] = cls.WEIGHTS["has_bidi"]
        if encoding.get("has_null_bytes"):
            signals["has_null_bytes"] = cls.WEIGHTS["has_null_bytes"]
        if encoding.get("has_control_chars"):
            signals["has_control_chars"] = cls.WEIGHTS["has_control_chars"]
        if encoding.get("has_mixed_scripts"):
            signals["has_mixed_scripts"] = cls.WEIGHTS["has_mixed_scripts"]
        if encoding.get("is_high_entropy"):
            signals["high_entropy"] = cls.WEIGHTS["high_entropy"]

        # ─── 4. Multiple encodings ───
        encodings = PayloadDecoder.detect_encoding(value)
        active_encodings = [k for k, v in encodings.items() if v]
        if len(active_encodings) >= 2:
            signals["multiple_encodings"] = cls.WEIGHTS["multiple_encodings"]

        # ─── 5. Behavioral indicators ───
        if len(value) > 1000:
            signals["excessive_length"] = cls.WEIGHTS["excessive_length"]

        special_ratio = cls._special_char_ratio(value)
        if special_ratio > 0.3:
            signals["special_char_ratio"] = cls.WEIGHTS["special_char_ratio"]

        if cls._has_repeated_chars(value):
            signals["repeated_chars"] = cls.WEIGHTS["repeated_chars"]

        return signals

    # ─── Score Calculation ─────────────────────────────────

    @classmethod
    def _calculate_score(cls, signals: Dict[str, int]) -> int:
        """
        بيحسب الدرجة النهائية.

        نستخدم logarithmic scale عشان:
        - إشارة واحدة = خطورة عالية
        - إشارات كتير = خطورة عالية جداً (بس مش 200)
        """
        if not signals:
            return 0

        # مجموع الأوزان
        total_weight = sum(signals.values())

        # عدد الإشارات
        signal_count = len(signals)

        # Logarithmic combination
        # score = min(100, total_weight * (1 - 0.1^(signal_count-1)))
        # عشان:
        # - إشارة واحدة = total_weight
        # - إشارتين = total_weight * 1.1
        # - 3 إشارات = total_weight * 1.11
        # - إلخ

        if signal_count == 1:
            score = total_weight
        else:
            multiplier = 1 + (signal_count - 1) * 0.1
            score = int(total_weight * multiplier)

        return min(score, 100)

    @classmethod
    def _get_level(cls, score: int) -> str:
        """بيرجع المستوى."""
        if score == 0:
            return "clean"
        if score < cls.THRESHOLD_LOW:
            return "clean"
        if score < cls.THRESHOLD_MEDIUM:
            return "low"
        if score < cls.THRESHOLD_HIGH:
            return "medium"
        if score < cls.THRESHOLD_CRITICAL:
            return "high"
        return "critical"

    # ─── Basic Detectors (من input_validator) ──────────────

    @staticmethod
    def _detect_sql_injection(value: str) -> bool:
        """SQL Injection."""
        import re
        patterns = [
            r"(\bunion\b.*\bselect\b)",
            r"(\bselect\b.*\bfrom\b.*\bwhere\b)",
            r"(;?\s*drop\s+table)",
            r"('\s*or\s+'1'\s*=\s*'1)",
            r"('\s*or\s+1\s*=\s*1)",
            r"(\bsleep\b\s*\()",
            r"(\bbenchmark\b\s*\()",
            r"(\bwaitfor\b\s+\bdelay\b)",
        ]
        lower = value.lower()
        return any(re.search(p, lower, re.IGNORECASE) for p in patterns)

    @staticmethod
    def _detect_xss(value: str) -> bool:
        """XSS."""
        import re
        patterns = [
            r"(<script[^>]*>)",
            r"(javascript\s*:)",
            r"(on\w+\s*=)",
            r"(<iframe)",
            r"(document\.cookie)",
        ]
        return any(re.search(p, value, re.IGNORECASE) for p in patterns)

    @staticmethod
    def _detect_command_injection(value: str) -> bool:
        """Command Injection."""
        import re
        patterns = [
            r"(;\s*(ls|cat|whoami|id|pwd|rm|wget|curl|bash|sh|nc|nmap)\b)",
            r"(\|\s*(ls|cat|whoami|id|pwd|bash|sh|nc)\b)",
            r"(`[^`]*`)",
            r"(\$\([^)]*\))",
        ]
        return any(re.search(p, value, re.IGNORECASE) for p in patterns)

    @staticmethod
    def _detect_path_traversal(value: str) -> bool:
        """Path Traversal."""
        import re
        patterns = [
            r"(\.\./)",
            r"(\.\.\\)",
            r"(%2e%2e%2f)",
            r"(/etc/passwd)",
            r"(/etc/shadow)",
            r"(c:\\windows)",
        ]
        return any(re.search(p, value, re.IGNORECASE) for p in patterns)

    # ─── Behavioral Helpers ────────────────────────────────

    @staticmethod
    def _special_char_ratio(value: str) -> float:
        """نسبة الحروف الخاصة."""
        if not value:
            return 0.0
        special = sum(1 for c in value if not c.isalnum() and not c.isspace())
        return special / len(value)

    @staticmethod
    def _has_repeated_chars(value: str, threshold: int = 20) -> bool:
        """بيفحص لو فيه حروف متكررة كتير."""
        if not value or len(value) < threshold:
            return False
        # فحص بسيط: هل فيه نفس الحرف مكرر threshold مرة؟
        for i in range(len(value) - threshold):
            if len(set(value[i:i+threshold])) == 1:
                return True
        return False

    # ─── Batch Scoring ─────────────────────────────────────

    @classmethod
    def score_dict(
        cls,
        data: Dict[str, Any],
        parent_key: str = "",
    ) -> Dict[str, Any]:
        """
        بيقيّم كل القيم في dict.

        Returns:
            dict فيه:
            - max_score: أعلى درجة
            - worst_field: الحقل الأخطر
            - all_signals: كل الإشارات
            - results: نتائج كل حقل
        """
        if not isinstance(data, dict):
            return {"max_score": 0, "worst_field": None, "all_signals": {}, "results": {}}

        results: Dict[str, Any] = {}
        max_score = 0
        worst_field: Optional[str] = None
        all_signals: Dict[str, int] = {}

        for key, value in data.items():
            full_key = f"{parent_key}.{key}" if parent_key else key

            if isinstance(value, str):
                result = cls.score(value, full_key)
                results[full_key] = result

                if result["score"] > max_score:
                    max_score = result["score"]
                    worst_field = full_key

                for sig, weight in result["signals"].items():
                    all_signals[sig] = max(all_signals.get(sig, 0), weight)

            elif isinstance(value, dict):
                nested = cls.score_dict(value, full_key)
                results.update(nested["results"])

                if nested["max_score"] > max_score:
                    max_score = nested["max_score"]
                    worst_field = nested["worst_field"]

                for sig, weight in nested["all_signals"].items():
                    all_signals[sig] = max(all_signals.get(sig, 0), weight)

        return {
            "max_score": max_score,
            "worst_field": worst_field,
            "all_signals": all_signals,
            "results": results,
        }

    # ─── Helpers ───────────────────────────────────────────

    @classmethod
    def get_level_color(cls, level: str) -> str:
        """بيرجع لون للعرض."""
        colors = {
            "clean": "green",
            "low": "blue",
            "medium": "yellow",
            "high": "orange",
            "critical": "red",
            "empty": "gray",
        }
        return colors.get(level, "gray")

    @classmethod
    def get_recommendation(cls, score: int) -> str:
        """بيرجع توصية."""
        if score == 0:
            return "Allow"
        if score < cls.THRESHOLD_LOW:
            return "Allow (with logging)"
        if score < cls.THRESHOLD_MEDIUM:
            return "Monitor (increase logging)"
        if score < cls.THRESHOLD_HIGH:
            return "Challenge (rate limit or CAPTCHA)"
        if score < cls.THRESHOLD_CRITICAL:
            return "Block (return 400)"
        return "Block + Alert (return 403 + notify)"


# ─── Singleton ─────────────────────────────────────────────

heuristic_scorer = HeuristicScorer()