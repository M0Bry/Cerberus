"""
Context Validator — Validates inputs based on their context.

بيفحص المدخلات حسب السياق:
- Field-specific rules (email, url, uuid, ...)
- Type-aware (query, path, body, header)
- Strict vs Lenient
- Length limits
- Format validation
- Whitelist/Blacklist
- Method-aware

ملف مستقل.
"""

import re
from typing import Any, Dict, List, Optional, Set

import structlog

from app.core.heuristic_scorer import HeuristicScorer

logger = structlog.get_logger()


class ContextValidator:
    """
    كلاس لفحص المدخلات حسب السياق.

    بيوفر:
    - Field-specific validation
    - Type-aware validation
    - Length limits
    - Format validation
    """

    # ─── Field Rules ───────────────────────────────────────
    FIELD_RULES: Dict[str, Dict[str, Any]] = {
        # Email
        "email": {
            "pattern": r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
            "max_length": 254,
            "strict": True,
            "score_threshold": 20,
        },
        # URL
        "url": {
            "pattern": r"^https?://[^\s]+$",
            "max_length": 2048,
            "strict": True,
        },
        # Domain
        "domain": {
            "pattern": r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$",
            "max_length": 253,
            "strict": True,
        },
        # IP
        "ip": {
            "pattern": r"^(\d{1,3}\.){3}\d{1,3}$",
            "max_length": 15,
            "strict": True,
        },
        # UUID
        "uuid": {
            "pattern": r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            "max_length": 36,
            "strict": True,
        },
        # Password (سماح أوسع)
        "password": {
            "max_length": 128,
            "min_length": 8,
            "strict": False,
            "score_threshold": 30,
        },
        # Username
        "username": {
            "pattern": r"^[a-zA-Z0-9_.-]+$",
            "max_length": 50,
            "strict": True,
        },
        # Name (سماح أوسع - ممكن يكون فيه عربي/رموز)
        "name": {
            "max_length": 255,
            "strict": False,
            "score_threshold": 25,
        },
        # Description / Comment / Bio
        "description": {
            "max_length": 5000,
            "strict": False,
            "score_threshold": 30,
        },
        "comment": {
            "max_length": 5000,
            "strict": False,
            "score_threshold": 30,
        },
        "bio": {
            "max_length": 2000,
            "strict": False,
            "score_threshold": 30,
        },
        # Search query
        "search": {
            "max_length": 500,
            "strict": False,
            "score_threshold": 25,
        },
        "q": {
            "max_length": 500,
            "strict": False,
            "score_threshold": 25,
        },
        # Phone
        "phone": {
            "pattern": r"^\+?[\d\s\-\(\)]{7,20}$",
            "max_length": 20,
            "strict": True,
        },
        "phone_number": {
            "pattern": r"^\+?[\d\s\-\(\)]{7,20}$",
            "max_length": 20,
            "strict": True,
        },
        # Path / filename
        "path": {
            "pattern": r"^[a-zA-Z0-9_\-./]+$",
            "max_length": 500,
            "strict": True,
        },
        "filename": {
            "pattern": r"^[a-zA-Z0-9_\-.]+\.[a-zA-Z0-9]{1,10}$",
            "max_length": 255,
            "strict": True,
        },
        # Token / API Key
        "token": {
            "max_length": 2048,
            "strict": False,
            "score_threshold": 40,
        },
        "api_key": {
            "max_length": 512,
            "strict": False,
            "score_threshold": 40,
        },
        # Default
        "_default": {
            "max_length": 10000,
            "strict": False,
            "score_threshold": 20,
        },
    }

    # ─── Type Rules ────────────────────────────────────────
    TYPE_RULES: Dict[str, Dict[str, Any]] = {
        "query": {
            "max_length": 2000,
            "score_threshold": 20,
        },
        "path": {
            "max_length": 500,
            "score_threshold": 15,
        },
        "body": {
            "max_length": 10000,
            "score_threshold": 25,
        },
        "header": {
            "max_length": 8192,
            "score_threshold": 20,
        },
    }

    # ─── Main API ──────────────────────────────────────────

    @classmethod
    def validate(
        cls,
        value: str,
        field_name: str,
        context_type: str = "body",
        custom_rules: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        بيفحص قيمة حسب السياق.

        Args:
            value: القيمة
            field_name: اسم الحقل (زي email, password, search)
            context_type: query / path / body / header
            custom_rules: قواعد مخصصة

        Returns:
            dict فيه:
            - valid: bool
            - score: خطورة
            - reasons: أسباب الرفض
            - sanitized: القيمة المنضفة
        """
        if not isinstance(value, str):
            return cls._invalid_result("not_a_string")

        # 1. اجمع القواعد
        rules = cls._get_rules(field_name, context_type, custom_rules)

        # 2. افحص الطول
        length_issue = cls._check_length(value, rules)
        if length_issue:
            return cls._invalid_result(length_issue, value=value)

        # 3. افحص الشكل (pattern)
        if rules.get("pattern"):
            if not re.match(rules["pattern"], value):
                return cls._invalid_result("pattern_mismatch", value=value)

        # 4. افحص الخطورة (heuristic)
        threshold = rules.get("score_threshold", 20)
        score_result = HeuristicScorer.score(value, field_name)

        if score_result["score"] >= threshold:
            logger.warning(
                "context_validation_failed",
                field=field_name,
                type=context_type,
                score=score_result["score"],
                threshold=threshold,
            )
            return {
                "valid": False,
                "score": score_result["score"],
                "reasons": [f"threat_score_{score_result['score']}_above_{threshold}"],
                "signals": list(score_result["signals"].keys()),
                "sanitized": None,
            }

        # 5. نجح
        return {
            "valid": True,
            "score": score_result["score"],
            "reasons": [],
            "signals": list(score_result["signals"].keys()),
            "sanitized": value,
        }

    @classmethod
    def _get_rules(
        cls,
        field_name: str,
        context_type: str,
        custom_rules: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        بيجمع القواعد من كل المصادر.

        الأولوية:
        1. Default rules
        2. Type rules
        3. Field rules (exact match أولاً، بعدين longest substring match)
        4. Custom rules (أعلى أولوية)
        """
        rules = {}

        # 1. Default rules
        rules.update(cls.FIELD_RULES["_default"])

        # 2. Type rules
        if context_type in cls.TYPE_RULES:
            rules.update(cls.TYPE_RULES[context_type])

        # 3. Field rules
        field_lower = field_name.lower()

        # 3a. Exact match أولاً (أعلى أولوية)
        if field_lower in cls.FIELD_RULES:
            rules.update(cls.FIELD_RULES[field_lower])
        else:
            # 3b. Longest substring match — الأطول الأول
            # نرتب المفاتيح حسب الطول (تنازلياً)
            sorted_keys = sorted(
                [k for k in cls.FIELD_RULES.keys() if k != "_default"],
                key=len,
                reverse=True,
            )
            for key in sorted_keys:
                if key in field_lower:
                    rules.update(cls.FIELD_RULES[key])
                    break

        # 4. Custom rules (أعلى أولوية)
        if custom_rules:
            rules.update(custom_rules)

        return rules

    @classmethod
    def _check_length(cls, value: str, rules: Dict[str, Any]) -> Optional[str]:
        """بيفحص الطول."""
        max_length = rules.get("max_length")
        min_length = rules.get("min_length")

        if max_length and len(value) > max_length:
            return f"too_long_{len(value)}_max_{max_length}"

        if min_length and len(value) < min_length:
            return f"too_short_{len(value)}_min_{min_length}"

        return None

    @staticmethod
    def _invalid_result(reason: str, value: Optional[str] = None) -> Dict[str, Any]:
        """نتيجة رفض."""
        return {
            "valid": False,
            "score": 0,
            "reasons": [reason],
            "signals": [],
            "sanitized": None,
        }

    # ─── Batch Validation ──────────────────────────────────

    @classmethod
    def validate_dict(
        cls,
        data: Dict[str, Any],
        context_type: str = "body",
        parent_key: str = "",
    ) -> Dict[str, Any]:
        """
        بيفحص كل القيم في dict.

        Returns:
            dict فيه:
            - valid: bool (كل الحقول سليمة)
            - results: نتائج كل حقل
            - worst_score: أعلى درجة
            - worst_field: الحقل الأخطر
        """
        if not isinstance(data, dict):
            return {"valid": True, "results": {}, "worst_score": 0, "worst_field": None}

        results: Dict[str, Any] = {}
        max_score = 0
        worst_field: Optional[str] = None
        all_valid = True

        for key, value in data.items():
            full_key = f"{parent_key}.{key}" if parent_key else key

            if isinstance(value, str):
                result = cls.validate(value, key, context_type)
                results[full_key] = result

                if not result["valid"]:
                    all_valid = False

                if result["score"] > max_score:
                    max_score = result["score"]
                    worst_field = full_key

            elif isinstance(value, dict):
                nested = cls.validate_dict(value, context_type, full_key)
                results.update(nested["results"])

                if not nested["valid"]:
                    all_valid = False

                if nested["worst_score"] > max_score:
                    max_score = nested["worst_score"]
                    worst_field = nested["worst_field"]

        return {
            "valid": all_valid,
            "results": results,
            "worst_score": max_score,
            "worst_field": worst_field,
        }

    # ─── Format Helpers ────────────────────────────────────

    @staticmethod
    def is_email(value: str) -> bool:
        """بيفحص لو الإيميل صح."""
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return bool(re.match(pattern, value))

    @staticmethod
    def is_url(value: str) -> bool:
        """بيفحص لو الـ URL صح."""
        pattern = r"^https?://[^\s]+$"
        return bool(re.match(pattern, value))

    @staticmethod
    def is_uuid(value: str) -> bool:
        """بيفحص لو الـ UUID صح."""
        pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        return bool(re.match(pattern, value, re.IGNORECASE))

    @staticmethod
    def is_ipv4(value: str) -> bool:
        """بيفحص لو IPv4 صح."""
        pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        if not re.match(pattern, value):
            return False
        return all(0 <= int(octet) <= 255 for octet in value.split("."))

    @staticmethod
    def is_domain(value: str) -> bool:
        """بيفحص لو الـ domain صح."""
        pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$"
        return bool(re.match(pattern, value))

    @staticmethod
    def is_phone(value: str) -> bool:
        """بيفحص لو الـ phone صح."""
        pattern = r"^\+?[\d\s\-\(\)]{7,20}$"
        return bool(re.match(pattern, value))

    # ─── Utility ───────────────────────────────────────────

    @classmethod
    def add_field_rule(cls, field_name: str, rules: Dict[str, Any]) -> None:
        """بيضيف قاعدة جديدة لحقل."""
        cls.FIELD_RULES[field_name.lower()] = rules

    @classmethod
    def get_field_rules(cls, field_name: str) -> Dict[str, Any]:
        """
        بيرجع قواعد حقل.

        الأولوية:
        1. Exact match
        2. Longest substring match
        3. Default
        """
        field_lower = field_name.lower()

        # 1. Exact match
        if field_lower in cls.FIELD_RULES:
            return cls.FIELD_RULES[field_lower]

        # 2. Longest substring match
        sorted_keys = sorted(
            [k for k in cls.FIELD_RULES.keys() if k != "_default"],
            key=len,
            reverse=True,
        )
        for key in sorted_keys:
            if key in field_lower:
                return cls.FIELD_RULES[key]

        # 3. Default
        return cls.FIELD_RULES["_default"]


# ─── Singleton ─────────────────────────────────────────────

context_validator = ContextValidator()