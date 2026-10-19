"""
Input Validator — Sanitizes all user input against injection attacks.

بيوفر:
- كشف SQL Injection, XSS, Command Injection, Path Traversal
- فحص الطلب كله (Query + Path + Body)
- فحص القواميس المتداخلة (recursive)
- تكامل مع FastAPI (HTTPException)
- Logging لكل محاولة هجوم
- Advanced Validation (اختياري) — يستخدم الملفات الجديدة
"""

import html
import json
import logging
import re
from typing import Any, Dict, List, Optional

from fastapi import HTTPException, status

logger = logging.getLogger(__name__)


# ─── Attack Patterns ──────────────────────────────────────────

_SQLI_PATTERNS = [
    r"(\bunion\b.*\bselect\b)",
    r"(;?\s*drop\s+table)",
    r"(--\s*$)",
    r"('\s*or\s+'1'\s*=\s*'1)",
    r"('\s*or\s+1\s*=\s*1)",
    r"(\bor\b\s+1\s*=\s*1)",
    r"(\binsert\s+into\s+[\w]+\s*\()",
    r"(\bdelete\s+from\s+[\w]+\s*(where|;|$|\(|,))",
    r"(\bupdate\s+[\w]+\s+set\s+[\w]+\s*=)",
    r"(\bwaitfor\b\s+\bdelay\b)"
]

_XSS_PATTERNS = [
    r"(<script[^>]*>)",
    r"(javascript\s*:)",
    r"(on(?:error|load|click|change|submit|focus|blur|input|keydown|keyup|keypress|mouseover|mouseout|mousedown|mouseup|pointerdown|pointerup|dragstart|dragend|animationstart|animationend|transitionend|touchstart)\s*=)",
    r"(<iframe)",
    r"(<object)",
    r"(<embed)",
    r"(<svg[^>]*onload)",
    r"(<img[^>]*onerror)",
    r"(document\.cookie)",
    r"(document\.write)"
]

_CMDI_PATTERNS = [
    r"(;\s*(ls|cat|whoami|id|pwd|rm|wget|curl|bash|sh|nc|nmap)\b)",
    r"(\|\s*(ls|cat|whoami|id|pwd|bash|sh|nc)\b)",
    r"(&&\s*(ls|cat|whoami|id|pwd|rm|wget|curl|bash|sh)\b)"
]

_PATH_TRAVERSAL = [
    r"(\.\./)",
    r"(\.\.\\)",
    r"(%2e%2e%2f)",
    r"(%2e%2e/)",
    r"(%252e%252e%252f)",
    r"(/etc/passwd)",
    r"(/etc/shadow)",
    r"(c:\\windows)",
    r"(\.\.%2f)",
    r"(\.\.%5c)",
]

# CRLF Injection — أنماط في الـ URL الخام
_CRLF_PATTERNS = [
    "%0d%0a",
    "%0d",
    "%0a",
    "%5cr%5cn",
    "\\r\\n",
    "%23%0a",     # # + \n
    "%23%0d",     # # + \r
    "%23%0d%0a",  # # + \r\n
]


# ─── Sanitization ─────────────────────────────────────────────

def sanitize_string(value: str, max_length: int = 10000) -> str:
    """بتنضف النص (strip + escape)."""
    if not isinstance(value, str):
        return value
    value = value.strip()[:max_length]
    return html.escape(value)


# ─── Detection Functions ──────────────────────────────────────

def detect_sql_injection(value: str) -> bool:
    """بتدور على أنماط SQL Injection."""
    lower = value.lower()
    return any(re.search(p, lower, re.IGNORECASE) for p in _SQLI_PATTERNS)


def detect_xss(value: str) -> bool:
    """بتدور على أنماط XSS."""
    return any(re.search(p, value, re.IGNORECASE) for p in _XSS_PATTERNS)


def detect_command_injection(value: str) -> bool:
    """بتدور على أنماط Command Injection."""
    return any(re.search(p, value, re.IGNORECASE) for p in _CMDI_PATTERNS)


def detect_path_traversal(value: str) -> bool:
    """بتدور على أنماط Path Traversal."""
    return any(re.search(p, value, re.IGNORECASE) for p in _PATH_TRAVERSAL)


def detect_crlf_in_url(url: str) -> Optional[str]:
    """
    بتدور على CRLF Injection في نص الـ URL.

    Returns:
        الـ pattern لو موجود، أو None
    """
    if not isinstance(url, str):
        return None

    url_lower = url.lower()
    for pattern in _CRLF_PATTERNS:
        if pattern in url_lower:
            return pattern

    return None


def detect_crlf_in_raw_request(request) -> Optional[str]:
    """
    بتدور على CRLF Injection في الـ raw request data.

    بتفحص:
    - raw query string (bytes)
    - raw path (bytes)
    - request.url (نص)
    - الأحرف الفعلية \\r \\n

    Returns:
        وصف الـ pattern لو موجود، أو None
    """
    try:
        # 1. الـ raw query string
        raw_query = request.scope.get("query_string", b"")
        if isinstance(raw_query, bytes):
            raw_query_str = raw_query.decode("latin-1", errors="ignore").lower()
            for pattern in _CRLF_PATTERNS:
                if pattern in raw_query_str:
                    return f"query:{pattern}"

        # 2. الـ raw path
        raw_path = request.scope.get("raw_path", b"")
        if isinstance(raw_path, bytes):
            raw_path_str = raw_path.decode("latin-1", errors="ignore").lower()
            for pattern in _CRLF_PATTERNS:
                if pattern in raw_path_str:
                    return f"path:{pattern}"

        # 3. الـ request.url (نص)
        url_str = str(request.url).lower()
        for pattern in _CRLF_PATTERNS:
            if pattern in url_str:
                return f"url:{pattern}"

        # 4. فحص الأحرف الفعلية \r \n
        if "\r" in url_str or "\n" in url_str:
            return "url:literal_crlf"

    except Exception as e:
        logger.error(f"CRLF detection error: {e}")

    return None


# ─── Validation Functions ─────────────────────────────────────

def validate_input(value: str, field_name: str = "input") -> str:
    """فحص شامل لنص واحد. بترمي ValueError لو لقيت هجوم."""
    if not isinstance(value, str):
        return value

    if detect_sql_injection(value):
        logger.warning(f"SQL Injection detected in '{field_name}': {value[:100]}")
        raise ValueError(f"SQL Injection detected in '{field_name}'")
    if detect_xss(value):
        logger.warning(f"XSS detected in '{field_name}': {value[:100]}")
        raise ValueError(f"XSS attempt detected in '{field_name}'")
    if detect_command_injection(value):
        logger.warning(f"Command Injection detected in '{field_name}': {value[:100]}")
        raise ValueError(f"Command Injection detected in '{field_name}'")
    if detect_path_traversal(value):
        logger.warning(f"Path Traversal detected in '{field_name}': {value[:100]}")
        raise ValueError(f"Path Traversal detected in '{field_name}'")

    return sanitize_string(value)


def validate_string(value: str, field_name: str = "input") -> str:
    """فحص نص واحد وبترمي HTTPException لو لقيت هجوم."""
    if not isinstance(value, str):
        return value

    if detect_sql_injection(value):
        logger.warning(f"SQL Injection detected in '{field_name}': {value[:100]}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Potential SQL Injection detected in '{field_name}'",
        )
    if detect_xss(value):
        logger.warning(f"XSS detected in '{field_name}': {value[:100]}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Potential XSS detected in '{field_name}'",
        )
    if detect_command_injection(value):
        logger.warning(f"Command Injection detected in '{field_name}': {value[:100]}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Potential Command Injection detected in '{field_name}'",
        )
    if detect_path_traversal(value):
        logger.warning(f"Path Traversal detected in '{field_name}': {value[:100]}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Potential Path Traversal detected in '{field_name}'",
        )

    return value


def validate_dict(data: Dict[str, Any], parent_key: str = "") -> Dict[str, Any]:
    """فحص قاموس بشكل متداخل (recursive)."""
    validated = {}
    for key, value in data.items():
        full_key = f"{parent_key}.{key}" if parent_key else key

        if isinstance(value, str):
            validated[key] = validate_string(value, full_key)
        elif isinstance(value, dict):
            validated[key] = validate_dict(value, full_key)
        elif isinstance(value, list):
            validated[key] = [
                validate_string(item, f"{full_key}[{i}]")
                if isinstance(item, str)
                else validate_dict(item, f"{full_key}[{i}]")
                if isinstance(item, dict)
                else item
                for i, item in enumerate(value)
            ]
        else:
            validated[key] = value

    return validated


async def validate_request(request) -> None:
    """فحص الطلب كله (Query Params + Path Params + Body)."""
    for key, value in request.query_params.items():
        validate_string(value, f"query.{key}")

    for key, value in request.path_params.items():
        validate_string(value, f"path.{key}")

    if request.method in ["POST", "PUT", "PATCH"]:
        try:
            body = await request.json()
            if isinstance(body, dict):
                validate_dict(body, "body")
            elif isinstance(body, list):
                for i, item in enumerate(body):
                    if isinstance(item, dict):
                        validate_dict(item, f"body[{i}]")
                    elif isinstance(item, str):
                        validate_string(item, f"body[{i}]")
        except json.JSONDecodeError:
            pass


# ─── Specific Validators ──────────────────────────────────────

def validate_email(email: str) -> bool:
    """بتتحقق من صحة الإيميل."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_domain(domain: str) -> bool:
    """بتتحقق من صحة الدومين."""
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
    return bool(re.match(pattern, domain))


def validate_ip(ip: str) -> bool:
    """بتتحقق من صحة الـ IP."""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    return all(0 <= int(octet) <= 255 for octet in ip.split('.'))


def validate_url(url: str) -> bool:
    """بتتحقق من صحة الـ URL."""
    pattern = r'^https?://[a-zA-Z0-9.-]+(:[0-9]+)?(/.*)?$'
    return bool(re.match(pattern, url))


# ═══════════════════════════════════════════════════════════════
# ─── Advanced Validation (Optional) ─────────────────────────────
# ═══════════════════════════════════════════════════════════════

from app.core.advanced_patterns import AdvancedPatterns
from app.core.context_validator import ContextValidator
from app.core.encoding_detector import EncodingDetector
from app.core.heuristic_scorer import HeuristicScorer
from app.core.ml_payload_detector import MLPayloadDetector
from app.core.payload_decoder import PayloadDecoder
from app.core.unicode_normalizer import UnicodeNormalizer


# ─── Singleton للـ ML Detector ─────────────────────────────────
# عشان نحمل الموديل مرة واحدة بس

_ml_detector_instance: Optional[MLPayloadDetector] = None


def _get_ml_detector() -> MLPayloadDetector:
    """Singleton للـ ML detector."""
    global _ml_detector_instance
    if _ml_detector_instance is None:
        _ml_detector_instance = MLPayloadDetector()
    return _ml_detector_instance


# ─── Scoring Constants ─────────────────────────────────────────

# أوزان إشارات Encoding
_ENCODING_SIGNAL_WEIGHTS = {
    "homoglyphs": 25,
    "zero_width": 20,
    "bidi": 25,
    "null_bytes": 30,
    "mixed_scripts": 20,
}


def validate_value_advanced(
    value: str,
    field_name: str = "input",
    context_type: str = "body",
    threshold: int = 30,
) -> dict:
    """
    فحص متقدم لقيمة واحدة.

    بيطبق:
    1. Unicode normalization
    2. Payload decoding
    3. Advanced patterns (XXE, SSRF, ...)
    4. Encoding detection
    5. Heuristic scoring
    6. ML detection
    7. Context validation

    Returns:
        dict فيه:
        - valid: bool
        - score: 0-100
        - issues: list
        - sanitized: القيمة المنضفة
    """
    if not isinstance(value, str):
        return {"valid": True, "score": 0, "issues": [], "sanitized": value}

    if not value:
        return {"valid": True, "score": 0, "issues": [], "sanitized": value}

    # 1. Unicode normalization
    normalized = UnicodeNormalizer.canonicalize(value)

    # 2. Payload decoding
    variants = PayloadDecoder.decode_all(normalized)

    # 3. ML detector (Singleton — مرة واحدة بس)
    ml_detector = _get_ml_detector()

    # 4. فحص كل variant
    max_score = 0
    all_issues: List[str] = []

    for variant in variants[:10]:
        # Advanced patterns
        advanced = AdvancedPatterns.detect_all(variant)
        for pattern_name, detected in advanced.items():
            if detected:
                all_issues.append(f"advanced.{pattern_name}")

        # Heuristic scoring
        heuristic = HeuristicScorer.score(variant, field_name)
        if heuristic["score"] > max_score:
            max_score = heuristic["score"]

        # ML detection
        try:
            ml = ml_detector.predict(variant)
            if ml["is_malicious"] and ml["score"] > max_score:
                max_score = ml["score"]
                all_issues.append("ml_detected")
        except Exception:
            pass

    # 5. Encoding detection (مع أوزان)
    encoding = EncodingDetector.detect_all(value)
    for signal, weight in _ENCODING_SIGNAL_WEIGHTS.items():
        if encoding.get(f"has_{signal}"):
            all_issues.append(signal)
            max_score = max(max_score, weight)

    # 6. Context validation
    try:
        context_result = ContextValidator.validate(value, field_name, context_type)
        if not context_result["valid"]:
            # ضيف الأسباب
            for reason in context_result["reasons"]:
                all_issues.append(reason)

            # لو pattern_mismatch → فشل صريح، ارفع الـ score
            if "pattern_mismatch" in context_result["reasons"]:
                max_score = max(max_score, threshold + 10)

            # لو threat score → استخدمه
            elif context_result["score"] > max_score:
                max_score = context_result["score"]
    except Exception:
        pass

    # 7. القرار
    valid = max_score < threshold

    return {
        "valid": valid,
        "score": max_score,
        "issues": list(set(all_issues)),
        "sanitized": normalized if valid else None,
    }


async def validate_request_advanced(
    request,
    threshold: int = 30,
) -> dict:
    """
    فحص متقدم للطلب كله.

    Returns:
        dict فيه:
        - valid: bool
        - max_score: int
        - worst_field: str
        - issues: dict
        - total_checks: int
    """
    issues_dict: Dict[str, List[str]] = {}
    max_score = 0
    worst_field: Optional[str] = None
    total_checks = 0

    # ─── 0. CRLF Injection Check (على الـ raw request) ───
    crlf_pattern = detect_crlf_in_raw_request(request)
    if crlf_pattern:
        logger.warning(
            f"CRLF injection detected: pattern={crlf_pattern}, "
            f"url={str(request.url)[:200]}"
        )
        return {
            "valid": False,
            "max_score": 100,
            "worst_field": "url",
            "issues": {"url": [f"crlf_injection:{crlf_pattern}"]},
            "total_checks": 1,
        }

    # ─── 1. Query Params ───
    for key, value in request.query_params.items():
        result = validate_value_advanced(value, f"query.{key}", "query", threshold)
        total_checks += 1
        if not result["valid"]:
            issues_dict[f"query.{key}"] = result["issues"]
            if result["score"] > max_score:
                max_score = result["score"]
                worst_field = f"query.{key}"

    # ─── 2. Path Params ───
    for key, value in request.path_params.items():
        result = validate_value_advanced(value, f"path.{key}", "path", threshold)
        total_checks += 1
        if not result["valid"]:
            issues_dict[f"path.{key}"] = result["issues"]
            if result["score"] > max_score:
                max_score = result["score"]
                worst_field = f"path.{key}"

    # ─── 3. Headers (المهمة بس) ───
    important_headers = [
        "user-agent", "referer", "x-forwarded-for",
        "x-forwarded-host", "authorization",
    ]
    for key, value in request.headers.items():
        if key.lower() in important_headers:
            result = validate_value_advanced(
                value, f"header.{key}", "header", threshold
            )
            total_checks += 1
            if not result["valid"]:
                issues_dict[f"header.{key}"] = result["issues"]
                if result["score"] > max_score:
                    max_score = result["score"]
                    worst_field = f"header.{key}"

    # ─── 4. Body ───
    if request.method in ["POST", "PUT", "PATCH"]:
        try:
            body = await request.json()
            if isinstance(body, dict):
                body_result = _validate_body_advanced(body, threshold)
                total_checks += body_result["total_checks"]
                if not body_result["valid"]:
                    issues_dict.update(body_result["issues"])
                    if body_result["max_score"] > max_score:
                        max_score = body_result["max_score"]
                        worst_field = body_result["worst_field"]
        except json.JSONDecodeError:
            pass
        except Exception:
            pass

    # ─── 5. القرار ───
    valid = max_score < threshold

    if not valid:
        logger.warning(
            f"Advanced validation failed: "
            f"worst_field={worst_field}, max_score={max_score}, "
            f"total_checks={total_checks}"
        )

    return {
        "valid": valid,
        "max_score": max_score,
        "worst_field": worst_field,
        "issues": issues_dict,
        "total_checks": total_checks,
    }


def _validate_body_advanced(
    body: Dict[str, Any],
    threshold: int = 30,
    parent_key: str = "body",
) -> dict:
    """فحص متقدم للـ Body (recursive)."""
    issues_dict: Dict[str, List[str]] = {}
    max_score = 0
    worst_field: Optional[str] = None
    total_checks = 0
    all_valid = True

    for key, value in body.items():
        full_key = f"{parent_key}.{key}"

        if isinstance(value, str):
            result = validate_value_advanced(value, full_key, "body", threshold)
            total_checks += 1
            if not result["valid"]:
                all_valid = False
                issues_dict[full_key] = result["issues"]
                if result["score"] > max_score:
                    max_score = result["score"]
                    worst_field = full_key

        elif isinstance(value, dict):
            nested = _validate_body_advanced(value, threshold, full_key)
            total_checks += nested["total_checks"]
            if not nested["valid"]:
                all_valid = False
                issues_dict.update(nested["issues"])
                if nested["max_score"] > max_score:
                    max_score = nested["max_score"]
                    worst_field = nested["worst_field"]

        elif isinstance(value, list):
            for i, item in enumerate(value):
                item_key = f"{full_key}[{i}]"
                if isinstance(item, str):
                    result = validate_value_advanced(
                        item, item_key, "body", threshold
                    )
                    total_checks += 1
                    if not result["valid"]:
                        all_valid = False
                        issues_dict[item_key] = result["issues"]
                        if result["score"] > max_score:
                            max_score = result["score"]
                            worst_field = item_key
                elif isinstance(item, dict):
                    nested = _validate_body_advanced(item, threshold, item_key)
                    total_checks += nested["total_checks"]
                    if not nested["valid"]:
                        all_valid = False
                        issues_dict.update(nested["issues"])
                        if nested["max_score"] > max_score:
                            max_score = nested["max_score"]
                            worst_field = nested["worst_field"]

    return {
        "valid": all_valid,
        "max_score": max_score,
        "worst_field": worst_field,
        "issues": issues_dict,
        "total_checks": total_checks,
    }